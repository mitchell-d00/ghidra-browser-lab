// GhidraScript: run from analyzeHeadless -postScript WebExport.java <output-json>
// @category BrowserLab
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class WebExport extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length != 1) {
            throw new IllegalArgumentException("WebExport requires an output JSON file path");
        }
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("program", currentProgram.getName());
        output.put("language", currentProgram.getLanguage().getLanguageID().getIdAsString());
        output.put("imageBase", currentProgram.getImageBase().toString());
        List<Map<String, Object>> functions = new ArrayList<>();
        output.put("functions", functions);

        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Ghidra decompiler could not open the program");
        }
        try {
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            int limit = 50;
            while (it.hasNext() && functions.size() < limit && !monitor.isCancelled()) {
                Function fn = it.next();
                if (fn.isExternal()) continue;
                Map<String, Object> func = new LinkedHashMap<>();
                func.put("name", fn.getName());
                func.put("entry", fn.getEntryPoint().toString());
                List<Map<String, String>> insns = new ArrayList<>();
                InstructionIterator code = currentProgram.getListing().getInstructions(fn.getBody(), true);
                while (code.hasNext() && insns.size() < 120) {
                    Instruction ins = code.next();
                    Map<String, String> record = new LinkedHashMap<>();
                    record.put("address", ins.getAddress().toString());
                    record.put("text", ins.toString());
                    byte[] raw = ins.getBytes();
                    StringBuilder hex = new StringBuilder();
                    for (int b = 0; b < Math.min(raw.length, 16); b++) {
                        if (b > 0) hex.append(' ');
                        hex.append(String.format("%02x", raw[b] & 255));
                    }
                    record.put("bytes", hex.toString());
                    insns.add(record);
                }
                func.put("instructions", insns);
                String pseudocode = "";
                try {
                    DecompileResults result = decompiler.decompileFunction(fn, 12, monitor);
                    if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
                        pseudocode = result.getDecompiledFunction().getC();
                    }
                } catch (Exception ex) {
                    pseudocode = "// Decompilation failed for this function: " + ex.getClass().getSimpleName();
                }
                func.put("decompiled", pseudocode.length() > 28000 ? pseudocode.substring(0, 28000) : pseudocode);
                functions.add(func);
            }
        } finally {
            decompiler.dispose();
        }
        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        Files.write(Paths.get(args[0]), gson.toJson(output).getBytes(StandardCharsets.UTF_8));
        println("Browser Lab: exported " + functions.size() + " functions");
    }
}
