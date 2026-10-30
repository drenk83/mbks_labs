/* Общие коды IOCTL для драйвера FsFilterX и программы fsctl.
   Оба проекта подключают этот файл, чтобы номера не разъехались. */
#pragma once

#define IOCTL_FSFILTERX_RELOAD \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_FSFILTERX_NOTIFY_ON \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_FSFILTERX_NOTIFY_OFF \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
