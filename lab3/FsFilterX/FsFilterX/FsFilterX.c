/* FsFilterX — минифильтр дискреционного доступа к файлам.
   Вариант 9: объекты файловой системы, права в XML, нотификатор загрузки образов.

   Субъект — имя exe. Файла нет в policy.xml — доступ разрешён, иначе
   действует список субъектов этого файла: нет строки или стоит 0 — отказ.
   Сам policy.xml открывает только fsctl.exe и поток, который его перечитывает.
   Правила перечитываются в DriverEntry и по IOCTL, не на каждой операции.
*/
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "ioctl.h"

#define MAX_NAME 256
#define MAX_FILES 32
#define MAX_SUBJECTS 8
#define POLICY_BYTES 8192

#define POLICY_PATH L"C:\\DriverConfig\\policy.xml"
#define POLICY_NT_PATH L"\\DosDevices\\C:\\DriverConfig\\policy.xml"
#define LOG_PATH L"C:\\DriverConfig\\image.log"
#define LOG_NT_PATH L"\\DosDevices\\C:\\DriverConfig\\image.log"
#define CONTROL_EXE L"fsctl.exe"
#define DEVICE_NAME L"\\Device\\FsFilterX"
#define DEVICE_LINK L"\\DosDevices\\FsFilterX"

typedef struct _SUBJECT {
    WCHAR Name[MAX_NAME];
    WCHAR ReadFlag;
    WCHAR WriteFlag;
} SUBJECT;

typedef struct _FILE_RULE {
    WCHAR Path[MAX_NAME];
    SUBJECT Subjects[MAX_SUBJECTS];
    int SubjectCount;
} FILE_RULE;

NTKERNELAPI PUCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);

typedef NTSTATUS(*QUERY_INFO_PROCESS)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

static PFLT_FILTER gFilter = NULL;
static PDEVICE_OBJECT gDevice = NULL;
static ERESOURCE gRuleLock;
static ERESOURCE gLogLock;
static FILE_RULE gRules[MAX_FILES];
static int gRuleCount = 0;
static FILE_RULE gStaging[MAX_FILES];
static int gStagingCount = 0;
static volatile LONG gLoadingPolicy = 0;
static PEPROCESS gPolicyReader = NULL;
static QUERY_INFO_PROCESS gQueryProcess = NULL;
static HANDLE gLogHandle = NULL;
static volatile LONG gNotifySet = 0;
static volatile LONG gInsideNotify = 0;

DRIVER_INITIALIZE DriverEntry;

static NTSTATUS DispatchCreate(PDEVICE_OBJECT Device, PIRP Irp);
static NTSTATUS DispatchClose(PDEVICE_OBJECT Device, PIRP Irp);
static NTSTATUS DispatchCleanup(PDEVICE_OBJECT Device, PIRP Irp);
static NTSTATUS DispatchIoctl(PDEVICE_OBJECT Device, PIRP Irp);
static NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
static NTSTATUS QueryTeardown(PCFLT_RELATED_OBJECTS Objects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);
static FLT_PREOP_CALLBACK_STATUS PreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Objects, PVOID* Context);
static FLT_PREOP_CALLBACK_STATUS PreRead(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Objects, PVOID* Context);
static FLT_PREOP_CALLBACK_STATUS PreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Objects, PVOID* Context);

static CONST FLT_OPERATION_REGISTRATION gCallbacks[] = {
    { IRP_MJ_CREATE, 0, PreCreate, NULL },
    { IRP_MJ_READ, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreRead, NULL },
    { IRP_MJ_WRITE, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreWrite, NULL },
    { IRP_MJ_OPERATION_END }
};

static CONST FLT_REGISTRATION gRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    gCallbacks,
    FilterUnload,
    NULL,
    QueryTeardown,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

static NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status)
{
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static int SameText(const WCHAR* left, const WCHAR* right)
{
    while (*left != 0 && *right != 0) {
        WCHAR a = *left;
        WCHAR b = *right;
        if (a >= L'A' && a <= L'Z')
            a = (WCHAR)(a - L'A' + L'a');
        if (b >= L'A' && b <= L'Z')
            b = (WCHAR)(b - L'A' + L'a');
        if (a != b)
            return 0;
        left++;
        right++;
    }
    return *left == *right;
}

static void KeepFileName(WCHAR* path)
{
    WCHAR* slash = NULL;
    WCHAR* cursor = path;
    int i;

    while (*cursor != 0) {
        if (*cursor == L'\\')
            slash = cursor;
        cursor++;
    }
    if (slash == NULL)
        return;
    slash++;
    i = 0;
    while (slash[i] != 0 && i < MAX_NAME - 1) {
        path[i] = slash[i];
        i++;
    }
    path[i] = 0;
}

static NTSTATUS QueryProcessImage(PEPROCESS process, WCHAR* dest, int destChars)
{
    HANDLE handle = NULL;
    UNICODE_STRING* image = NULL;
    ULONG bytes = 0;
    NTSTATUS status;
    size_t chars;

    dest[0] = 0;
    if (process == NULL || destChars < 2)
        return STATUS_INVALID_PARAMETER;

    status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL, 0, NULL, KernelMode, &handle);
    if (!NT_SUCCESS(status))
        return status;

    if (gQueryProcess == NULL) {
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, L"ZwQueryInformationProcess");
        gQueryProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&name);
        if (gQueryProcess == NULL) {
            ZwClose(handle);
            return STATUS_PROCEDURE_NOT_FOUND;
        }
    }

    status = gQueryProcess(handle, ProcessImageFileName, NULL, 0, &bytes);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        ZwClose(handle);
        return status;
    }

    image = ExAllocatePoolWithTag(NonPagedPoolNx, bytes, 'xsFF');
    if (image == NULL) {
        ZwClose(handle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = gQueryProcess(handle, ProcessImageFileName, image, bytes, &bytes);
    if (!NT_SUCCESS(status) || image->Buffer == NULL) {
        ExFreePoolWithTag(image, 'xsFF');
        ZwClose(handle);
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }

    chars = image->Length / sizeof(WCHAR);
    if (chars >= (size_t)destChars)
        chars = (size_t)destChars - 1;
    RtlCopyMemory(dest, image->Buffer, chars * sizeof(WCHAR));
    dest[chars] = 0;
    ExFreePoolWithTag(image, 'xsFF');
    ZwClose(handle);
    return STATUS_SUCCESS;
}

/* Короткое имя из EPROCESS, не длиннее 14 символов. Его можно читать на APC. */
static void CopyShortName(PEPROCESS process, WCHAR* dest, int destChars)
{
    const UCHAR* raw;
    int i;

    dest[0] = 0;
    if (process == NULL || destChars < 2)
        return;
    raw = PsGetProcessImageFileName(process);
    if (raw == NULL)
        return;
    for (i = 0; raw[i] != 0 && i < 14 && i < destChars - 1; i++)
        dest[i] = (WCHAR)raw[i];
    dest[i] = 0;
}

static void CurrentExeName(WCHAR* dest, int destChars)
{
    dest[0] = 0;
    if (KeGetCurrentIrql() == PASSIVE_LEVEL &&
        NT_SUCCESS(QueryProcessImage(PsGetCurrentProcess(), dest, destChars))) {
        KeepFileName(dest);
        if (dest[0] != 0)
            return;
    }
    CopyShortName(PsGetCurrentProcess(), dest, destChars);
}

static void RequestExeName(PFLT_CALLBACK_DATA data, WCHAR* dest, int destChars)
{
    PEPROCESS process;

    dest[0] = 0;
    process = IoThreadToProcess(data->Thread);
    if (KeGetCurrentIrql() == PASSIVE_LEVEL &&
        NT_SUCCESS(QueryProcessImage(process, dest, destChars))) {
        KeepFileName(dest);
        if (dest[0] != 0)
            return;
    }
    CopyShortName(process, dest, destChars);
}

static int IsControlProgram(const WCHAR* exeName)
{
    return SameText(exeName, CONTROL_EXE);
}

/* "\Device\HarddiskVolume3\dir\a.txt" -> "C:\dir\a.txt".
   Буква всегда C:, защищаемые файлы лежат на этом диске. */
static int VolumePathToC(const WCHAR* full, WCHAR* dest, int destChars)
{
    const WCHAR marker[] = L"HarddiskVolume";
    const int markerLen = 14;
    int i;
    int start = -1;
    int out;

    dest[0] = 0;
    for (i = 0; full[i] != 0 && i < MAX_NAME - markerLen; i++) {
        int k;
        int match = 1;
        for (k = 0; k < markerLen; k++) {
            if (full[i + k] != marker[k]) {
                match = 0;
                break;
            }
        }
        if (match) {
            start = i + markerLen;
            break;
        }
    }
    if (start < 0)
        return 0;
    while (full[start] >= L'0' && full[start] <= L'9')
        start++;
    if (destChars < 4)
        return 0;
    dest[0] = L'C';
    dest[1] = L':';
    out = 2;
    for (i = start; full[i] != 0 && out < destChars - 1; i++)
        dest[out++] = full[i];
    dest[out] = 0;
    return 1;
}

/* У CREATE в FileObject->FileName путь без буквы диска: "\dir\a.txt". */
static int CreatePathToC(PFLT_CALLBACK_DATA data, WCHAR* dest, int destChars)
{
    PFILE_OBJECT file;
    USHORT chars;
    USHORT i;
    int out;

    dest[0] = 0;
    file = data->Iopb->TargetFileObject;
    if (file == NULL || file->RelatedFileObject != NULL)
        return 0;
    if (file->FileName.Buffer == NULL || file->FileName.Length == 0)
        return 0;
    chars = file->FileName.Length / sizeof(WCHAR);
    if (chars == 0 || chars >= destChars - 2)
        return 0;
    dest[0] = L'C';
    dest[1] = L':';
    out = 2;
    for (i = 0; i < chars; i++)
        dest[out++] = file->FileName.Buffer[i];
    dest[out] = 0;
    return 1;
}

static int OperationPath(PFLT_CALLBACK_DATA data, WCHAR* dest, int destChars)
{
    PFLT_FILE_NAME_INFORMATION info = NULL;
    NTSTATUS status;
    WCHAR raw[MAX_NAME];
    USHORT chars;
    int ok = 0;

    dest[0] = 0;
    status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &info);
    if (!NT_SUCCESS(status))
        return 0;
    status = FltParseFileNameInformation(info);
    if (NT_SUCCESS(status) && info->Name.Buffer != NULL) {
        chars = info->Name.Length / sizeof(WCHAR);
        if (chars > 0 && chars < MAX_NAME) {
            RtlCopyMemory(raw, info->Name.Buffer, chars * sizeof(WCHAR));
            raw[chars] = 0;
            ok = VolumePathToC(raw, dest, destChars);
        }
    }
    FltReleaseFileNameInformation(info);
    return ok;
}

static const char* SkipSpace(const char* text)
{
    while (*text == ' ' || *text == '\t')
        text++;
    return text;
}

static int HasPrefix(const char* text, const char* prefix)
{
    while (*prefix != 0) {
        if (*text != *prefix)
            return 0;
        text++;
        prefix++;
    }
    return 1;
}

/* Копирует значение attr="..." в широкую строку. Пути в работе — латиница. */
static int ReadAttr(const char* line, const char* attr, WCHAR* dest, int destChars)
{
    const char* cursor = line;

    dest[0] = 0;
    while (*cursor != 0) {
        const char* a = attr;
        const char* c = cursor;
        while (*a != 0 && *c == *a) {
            a++;
            c++;
        }
        if (*a == 0 && *c == '"') {
            int n = 0;
            c++;
            while (*c != 0 && *c != '"' && n < destChars - 1) {
                if ((unsigned char)*c >= 128)
                    return 0;
                dest[n++] = (WCHAR)(unsigned char)*c;
                c++;
            }
            if (*c != '"')
                return 0;
            dest[n] = 0;
            return n > 0;
        }
        cursor++;
    }
    return 0;
}

static NTSTATUS ParsePolicy(const char* text)
{
    char line[MAX_NAME * 2];
    int fileIndex = -1;

    gStagingCount = 0;
    RtlZeroMemory(gStaging, sizeof(gStaging));

    while (*text != 0) {
        int length = 0;
        const char* start;

        while (*text != 0 && *text != '\n' && *text != '\r' && length < (int)sizeof(line) - 1)
            line[length++] = *text++;
        line[length] = 0;
        while (*text == '\n' || *text == '\r')
            text++;
        if (length == (int)sizeof(line) - 1 && *text != 0 && *text != '\n' && *text != '\r')
            return STATUS_DATA_ERROR;

        start = SkipSpace(line);
        if (HasPrefix(start, "<file ")) {
            if (gStagingCount >= MAX_FILES)
                return STATUS_DATA_ERROR;
            fileIndex = gStagingCount;
            if (!ReadAttr(start, "path=", gStaging[fileIndex].Path, MAX_NAME))
                return STATUS_DATA_ERROR;
            gStaging[fileIndex].SubjectCount = 0;
            gStagingCount++;
        } else if (HasPrefix(start, "<subject ")) {
            SUBJECT* subject;
            WCHAR flag[4];
            if (fileIndex < 0)
                return STATUS_DATA_ERROR;
            if (gStaging[fileIndex].SubjectCount >= MAX_SUBJECTS)
                return STATUS_DATA_ERROR;
            subject = &gStaging[fileIndex].Subjects[gStaging[fileIndex].SubjectCount];
            if (!ReadAttr(start, "name=", subject->Name, MAX_NAME))
                return STATUS_DATA_ERROR;
            if (!ReadAttr(start, "read=", flag, 4) || (flag[0] != L'0' && flag[0] != L'1') || flag[1] != 0)
                return STATUS_DATA_ERROR;
            subject->ReadFlag = flag[0];
            if (!ReadAttr(start, "write=", flag, 4) || (flag[0] != L'0' && flag[0] != L'1') || flag[1] != 0)
                return STATUS_DATA_ERROR;
            subject->WriteFlag = flag[0];
            gStaging[fileIndex].SubjectCount++;
        }
    }
    return STATUS_SUCCESS;
}

static void PublishRules(void)
{
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&gRuleLock, TRUE);
    RtlCopyMemory(gRules, gStaging, sizeof(gRules));
    gRuleCount = gStagingCount;
    ExReleaseResourceLite(&gRuleLock);
    KeLeaveCriticalRegion();
}

static NTSTATUS ReadWholeFile(const WCHAR* ntPath, char* buffer, ULONG bufferSize, ULONG* readBytes)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attrs;
    IO_STATUS_BLOCK io;
    HANDLE handle = NULL;
    LARGE_INTEGER offset;
    NTSTATUS status;

    *readBytes = 0;
    RtlInitUnicodeString(&name, ntPath);
    InitializeObjectAttributes(&attrs, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateFile(
        &handle,
        GENERIC_READ,
        &attrs,
        &io,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0);
    if (!NT_SUCCESS(status))
        return status;

    offset.QuadPart = 0;
    status = ZwReadFile(handle, NULL, NULL, NULL, &io, buffer, bufferSize - 1, &offset, NULL);
    if (status == STATUS_END_OF_FILE) {
        *readBytes = 0;
        status = STATUS_SUCCESS;
    } else if (NT_SUCCESS(status)) {
        *readBytes = (ULONG)io.Information;
        if (*readBytes >= bufferSize - 1)
            status = STATUS_BUFFER_OVERFLOW;
    }
    ZwClose(handle);
    return status;
}

static NTSTATUS ReloadPolicy(void)
{
    char* buffer;
    ULONG bytes = 0;
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;
    if (InterlockedCompareExchange(&gLoadingPolicy, 1, 0) != 0)
        return STATUS_DEVICE_BUSY;

    gPolicyReader = PsGetCurrentProcess();
    buffer = ExAllocatePoolWithTag(NonPagedPoolNx, POLICY_BYTES, 'ploP');
    if (buffer == NULL) {
        gPolicyReader = NULL;
        InterlockedExchange(&gLoadingPolicy, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(buffer, POLICY_BYTES);

    status = ReadWholeFile(POLICY_NT_PATH, buffer, POLICY_BYTES, &bytes);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND) {
        gStagingCount = 0;
        RtlZeroMemory(gStaging, sizeof(gStaging));
        PublishRules();
        status = STATUS_SUCCESS;
    } else if (NT_SUCCESS(status)) {
        buffer[bytes] = 0;
        status = ParsePolicy(buffer);
        if (NT_SUCCESS(status))
            PublishRules();
    }

    ExFreePoolWithTag(buffer, 'ploP');
    gPolicyReader = NULL;
    InterlockedExchange(&gLoadingPolicy, 0);
    return status;
}

/* ALLOW, если файл не описан. DENY, если описан, но процесса в списке нет. */
static int AccessAllowed(const WCHAR* path, const WCHAR* exeName, int isWrite)
{
    int allowed = 1;
    int i;

    if (SameText(path, LOG_PATH))
        return 1;

    if (SameText(path, POLICY_PATH)) {
        if (gLoadingPolicy && PsGetCurrentProcess() == gPolicyReader)
            return 1;
        return IsControlProgram(exeName);
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&gRuleLock, TRUE);
    for (i = 0; i < gRuleCount; i++) {
        int j;
        if (!SameText(gRules[i].Path, path))
            continue;
        allowed = 0;
        for (j = 0; j < gRules[i].SubjectCount; j++) {
            WCHAR flag;
            if (!SameText(gRules[i].Subjects[j].Name, exeName))
                continue;
            flag = isWrite ? gRules[i].Subjects[j].WriteFlag : gRules[i].Subjects[j].ReadFlag;
            allowed = (flag == L'1');
            break;
        }
        break;
    }
    ExReleaseResourceLite(&gRuleLock);
    KeLeaveCriticalRegion();
    return allowed;
}

static FLT_PREOP_CALLBACK_STATUS Deny(PFLT_CALLBACK_DATA data)
{
    data->IoStatus.Status = STATUS_ACCESS_DENIED;
    data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

static FLT_PREOP_CALLBACK_STATUS PreCreate(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID* context)
{
    WCHAR path[MAX_NAME];
    WCHAR exeName[MAX_NAME];
    ACCESS_MASK desired = 0;
    ULONG disposition;
    int wantsWrite;
    int wantsRead;

    UNREFERENCED_PARAMETER(objects);
    UNREFERENCED_PARAMETER(context);

    if (FlagOn(data->Iopb->IrpFlags, IRP_PAGING_IO))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (FlagOn(data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!CreatePathToC(data, path, MAX_NAME))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    RequestExeName(data, exeName, MAX_NAME);
    if (data->Iopb->Parameters.Create.SecurityContext != NULL)
        desired = data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    disposition = (data->Iopb->Parameters.Create.Options >> 24) & 0xFF;

    /* ofstream открывает файл с CREATE_ALWAYS и обнуляет его ещё до WRITE. */
    wantsWrite = (desired & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | GENERIC_ALL)) != 0
        || disposition == FILE_SUPERSEDE
        || disposition == FILE_CREATE
        || disposition == FILE_OVERWRITE
        || disposition == FILE_OVERWRITE_IF;
    wantsRead = (desired & (FILE_READ_DATA | GENERIC_READ | GENERIC_ALL)) != 0;

    if (wantsWrite && !AccessAllowed(path, exeName, 1))
        return Deny(data);
    if (wantsRead && !AccessAllowed(path, exeName, 0))
        return Deny(data);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS CheckDataOp(PFLT_CALLBACK_DATA data, int isWrite)
{
    WCHAR path[MAX_NAME];
    WCHAR exeName[MAX_NAME];

    if (FlagOn(data->Iopb->IrpFlags, IRP_PAGING_IO))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!OperationPath(data, path, MAX_NAME))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    RequestExeName(data, exeName, MAX_NAME);
    if (!AccessAllowed(path, exeName, isWrite))
        return Deny(data);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS PreRead(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID* context)
{
    UNREFERENCED_PARAMETER(objects);
    UNREFERENCED_PARAMETER(context);
    return CheckDataOp(data, 0);
}

static FLT_PREOP_CALLBACK_STATUS PreWrite(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID* context)
{
    UNREFERENCED_PARAMETER(objects);
    UNREFERENCED_PARAMETER(context);
    return CheckDataOp(data, 1);
}

static void AppendChar(char* line, int* used, int cap, char ch)
{
    if (*used < cap - 1)
        line[(*used)++] = ch;
}

static void AppendText(char* line, int* used, int cap, const char* text)
{
    while (*text != 0)
        AppendChar(line, used, cap, *text++);
}

static void AppendNumber(char* line, int* used, int cap, ULONG value)
{
    char digits[16];
    int n = 0;
    int i;
    if (value == 0) {
        AppendChar(line, used, cap, '0');
        return;
    }
    while (value > 0 && n < (int)sizeof(digits)) {
        digits[n++] = (char)('0' + (value % 10));
        value /= 10;
    }
    for (i = n - 1; i >= 0; i--)
        AppendChar(line, used, cap, digits[i]);
}

static void AppendWide(char* line, int* used, int cap, const WCHAR* text, int chars)
{
    int i;
    if (text == NULL)
        return;
    for (i = 0; i < chars && text[i] != 0; i++) {
        WCHAR ch = text[i];
        AppendChar(line, used, cap, (ch >= 32 && ch < 127) ? (char)ch : '?');
    }
}

static void AppendTwoDigits(char* line, int* used, int cap, USHORT value)
{
    AppendChar(line, used, cap, (char)('0' + (value / 10) % 10));
    AppendChar(line, used, cap, (char)('0' + value % 10));
}

static void WriteLogLine(HANDLE processId, const WCHAR* exeName, const UNICODE_STRING* image)
{
    char line[1024];
    int used = 0;
    LARGE_INTEGER now;
    LARGE_INTEGER local;
    TIME_FIELDS fields;
    IO_STATUS_BLOCK io;

    KeQuerySystemTime(&now);
    ExSystemTimeToLocalTime(&now, &local);
    RtlTimeToTimeFields(&local, &fields);

    AppendNumber(line, &used, sizeof(line), fields.Year);
    AppendChar(line, &used, sizeof(line), '-');
    AppendTwoDigits(line, &used, sizeof(line), fields.Month);
    AppendChar(line, &used, sizeof(line), '-');
    AppendTwoDigits(line, &used, sizeof(line), fields.Day);
    AppendChar(line, &used, sizeof(line), ' ');
    AppendTwoDigits(line, &used, sizeof(line), fields.Hour);
    AppendChar(line, &used, sizeof(line), ':');
    AppendTwoDigits(line, &used, sizeof(line), fields.Minute);
    AppendChar(line, &used, sizeof(line), ':');
    AppendTwoDigits(line, &used, sizeof(line), fields.Second);
    AppendText(line, &used, sizeof(line), " pid=");
    AppendNumber(line, &used, sizeof(line), HandleToUlong(processId));
    AppendText(line, &used, sizeof(line), " process=");
    AppendWide(line, &used, sizeof(line), exeName, MAX_NAME);
    AppendText(line, &used, sizeof(line), " image=");
    if (image != NULL && image->Buffer != NULL)
        AppendWide(line, &used, sizeof(line), image->Buffer, image->Length / sizeof(WCHAR));
    else
        AppendText(line, &used, sizeof(line), "-");
    AppendText(line, &used, sizeof(line), "\r\n");

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&gLogLock, TRUE);
    if (gLogHandle != NULL)
        ZwWriteFile(gLogHandle, NULL, NULL, NULL, &io, line, (ULONG)used, NULL, NULL);
    ExReleaseResourceLite(&gLogLock);
    KeLeaveCriticalRegion();
}

static VOID LoadImageNotify(PUNICODE_STRING fullImageName, HANDLE processId, PIMAGE_INFO imageInfo)
{
    PEPROCESS process = NULL;
    WCHAR exeName[MAX_NAME];

    UNREFERENCED_PARAMETER(imageInfo);
    if (InterlockedCompareExchange(&gInsideNotify, 1, 0) != 0)
        return;

    exeName[0] = 0;
    if (NT_SUCCESS(PsLookupProcessByProcessId(processId, &process))) {
        CopyShortName(process, exeName, MAX_NAME);
        ObDereferenceObject(process);
    }
    if (exeName[0] == 0)
        RtlCopyMemory(exeName, L"-", 2 * sizeof(WCHAR));
    WriteLogLine(processId, exeName, fullImageName);
    InterlockedExchange(&gInsideNotify, 0);
}

static NTSTATUS OpenLog(void)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attrs;
    IO_STATUS_BLOCK io;
    NTSTATUS status;

    RtlInitUnicodeString(&name, LOG_NT_PATH);
    InitializeObjectAttributes(&attrs, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateFile(
        &gLogHandle,
        FILE_APPEND_DATA | SYNCHRONIZE,
        &attrs,
        &io,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0);
    if (!NT_SUCCESS(status))
        gLogHandle = NULL;
    return status;
}

static void CloseLog(void)
{
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&gLogLock, TRUE);
    if (gLogHandle != NULL) {
        ZwClose(gLogHandle);
        gLogHandle = NULL;
    }
    ExReleaseResourceLite(&gLogLock);
    KeLeaveCriticalRegion();
}

static NTSTATUS NotifyOn(void)
{
    NTSTATUS status;

    if (gNotifySet)
        return STATUS_SUCCESS;
    status = OpenLog();
    if (!NT_SUCCESS(status))
        return status;
    status = PsSetLoadImageNotifyRoutine(LoadImageNotify);
    if (!NT_SUCCESS(status)) {
        CloseLog();
        return status;
    }
    gNotifySet = 1;
    return STATUS_SUCCESS;
}

static NTSTATUS NotifyOff(void)
{
    LARGE_INTEGER pause;

    if (!gNotifySet)
        return STATUS_SUCCESS;
    PsRemoveLoadImageNotifyRoutine(LoadImageNotify);
    gNotifySet = 0;
    /* Колбэк, который уже вошёл, дописывает строку и сам отпускает флаг. */
    pause.QuadPart = -10 * 1000 * 10;
    while (gInsideNotify)
        KeDelayExecutionThread(KernelMode, FALSE, &pause);
    CloseLog();
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchCreate(PDEVICE_OBJECT device, PIRP irp)
{
    UNREFERENCED_PARAMETER(device);
    return CompleteIrp(irp, STATUS_SUCCESS);
}

static NTSTATUS DispatchClose(PDEVICE_OBJECT device, PIRP irp)
{
    UNREFERENCED_PARAMETER(device);
    return CompleteIrp(irp, STATUS_SUCCESS);
}

static NTSTATUS DispatchCleanup(PDEVICE_OBJECT device, PIRP irp)
{
    UNREFERENCED_PARAMETER(device);
    return CompleteIrp(irp, STATUS_SUCCESS);
}

static NTSTATUS DispatchIoctl(PDEVICE_OBJECT device, PIRP irp)
{
    PIO_STACK_LOCATION stack;
    WCHAR exeName[MAX_NAME];
    ULONG code;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(device);
    stack = IoGetCurrentIrpStackLocation(irp);
    code = stack->Parameters.DeviceIoControl.IoControlCode;
    CurrentExeName(exeName, MAX_NAME);
    if (!IsControlProgram(exeName))
        return CompleteIrp(irp, STATUS_ACCESS_DENIED);

    switch (code) {
    case IOCTL_FSFILTERX_RELOAD:
        status = ReloadPolicy();
        break;
    case IOCTL_FSFILTERX_NOTIFY_ON:
        status = NotifyOn();
        break;
    case IOCTL_FSFILTERX_NOTIFY_OFF:
        status = NotifyOff();
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    return CompleteIrp(irp, status);
}

static NTSTATUS CreateControlDevice(PDRIVER_OBJECT driver)
{
    UNICODE_STRING deviceName;
    UNICODE_STRING linkName;
    NTSTATUS status;

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&linkName, DEVICE_LINK);
    status = IoCreateDevice(driver, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &gDevice);
    if (!NT_SUCCESS(status))
        return status;
    status = IoCreateSymbolicLink(&linkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(gDevice);
        gDevice = NULL;
        return status;
    }
    gDevice->Flags |= DO_BUFFERED_IO;
    gDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

static void DeleteControlDevice(void)
{
    UNICODE_STRING linkName;
    RtlInitUnicodeString(&linkName, DEVICE_LINK);
    IoDeleteSymbolicLink(&linkName);
    if (gDevice != NULL) {
        IoDeleteDevice(gDevice);
        gDevice = NULL;
    }
}

static NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS flags)
{
    UNREFERENCED_PARAMETER(flags);
    NotifyOff();
    DeleteControlDevice();
    FltUnregisterFilter(gFilter);
    ExDeleteResourceLite(&gRuleLock);
    ExDeleteResourceLite(&gLogLock);
    return STATUS_SUCCESS;
}

static NTSTATUS QueryTeardown(PCFLT_RELATED_OBJECTS objects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS flags)
{
    UNREFERENCED_PARAMETER(objects);
    UNREFERENCED_PARAMETER(flags);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(registryPath);

    /* Диспетчер фильтров запоминает эти процедуры и вызывает их для
       управляющего устройства. Поставить их нужно до FltRegisterFilter. */
    driver->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    driver->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    driver->MajorFunction[IRP_MJ_CLEANUP] = DispatchCleanup;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

    status = ExInitializeResourceLite(&gRuleLock);
    if (!NT_SUCCESS(status))
        return status;
    status = ExInitializeResourceLite(&gLogLock);
    if (!NT_SUCCESS(status)) {
        ExDeleteResourceLite(&gRuleLock);
        return status;
    }

    status = FltRegisterFilter(driver, &gRegistration, &gFilter);
    if (!NT_SUCCESS(status)) {
        ExDeleteResourceLite(&gRuleLock);
        ExDeleteResourceLite(&gLogLock);
        return status;
    }

    status = CreateControlDevice(driver);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilter);
        ExDeleteResourceLite(&gRuleLock);
        ExDeleteResourceLite(&gLogLock);
        return status;
    }

    status = ReloadPolicy();
    if (!NT_SUCCESS(status))
        DbgPrint("FsFilterX: policy was not applied, code 0x%08x\n", status);

    status = FltStartFiltering(gFilter);
    if (!NT_SUCCESS(status)) {
        DeleteControlDevice();
        FltUnregisterFilter(gFilter);
        ExDeleteResourceLite(&gRuleLock);
        ExDeleteResourceLite(&gLogLock);
    }
    return status;
}
