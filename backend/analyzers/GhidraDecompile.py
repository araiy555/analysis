# Ghidra headless post-analysis script
# Runs inside Ghidra's Jython environment to decompile all functions
# Usage: analyzeHeadless <project_dir> <project_name> -import <binary>
#        -postScript GhidraDecompile.py -deleteProject

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import Function
import json

MAX_FUNCTIONS = 100
MAX_OUTPUT_CHARS = 500000

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

program_name = currentProgram.getName()
lang = str(currentProgram.getLanguage().getLanguageID())
compiler = str(currentProgram.getCompilerSpec().getCompilerSpecID())
image_base = str(currentProgram.getImageBase())

# Collect all functions sorted by entry point
func_manager = currentProgram.getFunctionManager()
functions = list(func_manager.getFunctions(True))

results = []
errors = []
total_chars = 0

for func in functions[:MAX_FUNCTIONS]:
    if total_chars >= MAX_OUTPUT_CHARS:
        break
    try:
        result = decompiler.decompileFunction(func, 60, monitor)
        if result and result.decompiledFunction:
            c_code = result.decompiledFunction.getC()
            if c_code:
                entry = str(func.getEntryPoint())
                name = func.getName()
                signature = str(func.getSignature())
                func_data = {
                    "name": name,
                    "address": entry,
                    "signature": signature,
                    "decompiled": c_code,
                    "size": func.getBody().getNumAddresses(),
                }
                results.append(func_data)
                total_chars += len(c_code)
    except Exception as e:
        errors.append({"function": str(func.getName()), "error": str(e)})

output = {
    "program": program_name,
    "language": lang,
    "compiler": compiler,
    "image_base": image_base,
    "function_count": func_manager.getFunctionCount(),
    "decompiled_count": len(results),
    "functions": results,
    "errors": errors[:10],
}

# Print JSON to stdout (captured by Python caller)
print("GHIDRA_JSON_START")
print(json.dumps(output, ensure_ascii=False, indent=2))
print("GHIDRA_JSON_END")
