import idautils
import idc
import idaapi
import ida_xref

# List of input functions to search for
input_functions = [
    "fread", "fscanf", "read", "fgets", "fgetc", "scanf", "gets"
]

# List of unsafe functions to search for
unsafe_functions = [
    "strcpy", "sprintf", "strncpy", "memcpy", "memmove", "strcat", "vsprintf"
]

# Combine both lists for searching
all_target_functions = input_functions + unsafe_functions

def find_and_print_calls():
    for func_name in all_target_functions:
        # Get the effective address of the function by name
        ea = idc.get_name_ea_simple(func_name)
        if ea == idaapi.BADADDR:
            # Try prefixed versions (e.g., _fread, __imp_fread) as imports might have prefixes
            ea = idc.get_name_ea_simple("_" + func_name)
        if ea == idaapi.BADADDR:
            ea = idc.get_name_ea_simple("__imp_" + func_name)
        if ea == idaapi.BADADDR:
            ea = idc.get_name_ea_simple(func_name + "@4")  # For stdcall decorations, adjust as needed
        if ea == idaapi.BADADDR:
            print("Function not found: %s" % func_name)
            continue
        
        # Find all code references (calls) to this function
        found_calls = False
        for ref in idautils.XrefsTo(ea, ida_xref.XREF_ALL):
            # Check if it's a code reference (call)
            if ref.type in (ida_xref.fl_CN, ida_xref.fl_CF, ida_xref.fl_JN, ida_xref.fl_JF):
                print("Function: %s called from: 0x%08X" % (func_name, ref.frm))
                found_calls = True
        
        if not found_calls:
            print("No calls found for function: %s" % func_name)

# Дождаться автоанализа, иначе перекрёстных ссылок ещё нет.
idaapi.auto_wait()
find_and_print_calls()
# qexit закрывает IDA. Это нужно только при запуске idat -S, не из меню File → Script file.
if idaapi.cvar.batch:
    idaapi.qexit(0)