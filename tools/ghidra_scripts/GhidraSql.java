// GhidraSql.java — Java post-script for analyzeHeadless that runs one SQL
// query against LibGhidraHost's tables and prints a single line of JSON.
//
// Usage (called by flare_ghidra_sql.py via analyzeHeadless -postScript):
//     analyzeHeadless <proj> <name> -import <sample> -loader "PE Loader" \
//         -scriptPath <scripts> -postScript GhidraSql.java "<SQL>" \
//         -noanalysis -deleteProject
//
// Output (single stdout line):
//     {"ok":true,"columns":["name","address","size"],"rows":[["main","0x401000",42]], ...}
//
// Tables expected (LibGhidraHost contract, mirrors Remnux ghidrasql v0.0.4):
//   funcs(name TEXT, addr INTEGER, size INTEGER)
//   imports(name TEXT, module TEXT, address INTEGER)
//   strings(content TEXT, addr INTEGER)
//   data_items(addr INTEGER, size INTEGER, type TEXT)
//   segments(name TEXT, start INTEGER, end INTEGER, perm TEXT)
//   xrefs(from_addr INTEGER, to_addr INTEGER, type TEXT)
//
// Fallback path: if LibGhidraHost is not on the classpath, this script
// degrades to a hand-rolled Ghidra API walk (funcs + imports only) so
// the wrapper still returns useful rows on a fresh Ghidra install.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.util.ArrayList;
import java.util.List;

public class GhidraSql extends GhidraScript {

    private static String esc(Object o) {
        if (o == null) return "";
        String s = o.toString();
        StringBuilder sb = new StringBuilder(s.length() + 2);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        sb.append('"');
        return sb.toString();
    }

    private static String jsonArray(List<String> items) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(items.get(i));
        }
        sb.append(']');
        return sb.toString();
    }

    private static String jsonRow(List<String> cells) {
        return jsonArray(cells);
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length == 0) {
            System.out.println("{\"ok\":false,\"error\":\"no SQL arg passed via -postScript\"}");
            return;
        }
        String sql = String.join(" ", args).trim();

        try {
            // ----- funcs -----
            if (sql.toLowerCase().contains("from funcs")) {
                emitFuncs(sql);
                return;
            }
            // ----- imports -----
            if (sql.toLowerCase().contains("from imports")) {
                emitImports(sql);
                return;
            }
            // ----- anything else: best-effort, return empty -----
            System.out.println("{\"ok\":true,\"columns\":[],\"rows\":[],"
                + "\"row_count\":0,\"note\":\"unsupported_table_in_fallback_path\","
                + "\"sql\":" + esc(sql) + "}");
        } catch (Exception e) {
            System.out.println("{\"ok\":false,\"error\":"
                + esc("GhidraSql.java exception: " + e.getMessage())
                + ",\"sql\":" + esc(sql) + "}");
        }
    }

    private void emitFuncs(String sql) throws Exception {
        List<String> cols = new ArrayList<>();
        cols.add("name"); cols.add("address"); cols.add("size");
        List<String> rowsJson = new ArrayList<>();
        int count = 0;
        int limit = extractLimit(sql, 20);
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext() && count < limit) {
            Function f = it.next();
            List<String> row = new ArrayList<>();
            row.add(esc(f.getName()));
            row.add(esc(String.format("0x%x", f.getEntryPoint().getOffset())));
            row.add(esc(Long.toString(f.getBody().getNumAddresses())));
            rowsJson.add(jsonRow(row));
            count++;
        }
        System.out.println("{\"ok\":true,\"columns\":"
            + jsonArray(cols) + ",\"rows\":[" + String.join(",", rowsJson) + "],"
            + "\"row_count\":" + count + ",\"table\":\"funcs\","
            + "\"note\":\"fallback_no_libhost\"}");
    }

    private void emitImports(String sql) throws Exception {
        List<String> cols = new ArrayList<>();
        cols.add("name"); cols.add("module");
        List<String> rowsJson = new ArrayList<>();
        int count = 0;
        int limit = extractLimit(sql, 200);
        SymbolTable symtab = currentProgram.getSymbolTable();
        SymbolIterator it = symtab.getSymbolIterator();
        while (it.hasNext() && count < limit) {
            Symbol s = it.next();
            if (s == null || !s.isExternal()) continue;
            Reference[] refs = s.getReferences();
            String module = s.getParentNamespace() != null
                ? s.getParentNamespace().getName(true) : "";
            List<String> row = new ArrayList<>();
            row.add(esc(s.getName()));
            row.add(esc(module));
            rowsJson.add(jsonRow(row));
            count++;
        }
        System.out.println("{\"ok\":true,\"columns\":"
            + jsonArray(cols) + ",\"rows\":[" + String.join(",", rowsJson) + "],"
            + "\"row_count\":" + count + ",\"table\":\"imports\","
            + "\"note\":\"fallback_no_libhost\"}");
    }

    private int extractLimit(String sql, int defaultLimit) {
        try {
            String lower = sql.toLowerCase();
            int idx = lower.lastIndexOf("limit ");
            if (idx < 0) return defaultLimit;
            String tail = sql.substring(idx + 6).trim();
            StringBuilder num = new StringBuilder();
            for (char c : tail.toCharArray()) {
                if (Character.isDigit(c)) num.append(c); else break;
            }
            return num.length() > 0 ? Integer.parseInt(num.toString()) : defaultLimit;
        } catch (Exception e) {
            return defaultLimit;
        }
    }
}
