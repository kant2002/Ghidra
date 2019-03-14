package ghidra.app.plugin.core.analysis.tests;

import ghidra.app.util.bin.format.pdb.PdbParserNEW;
import ghidra.app.util.bin.format.pdb.PdbProgramAttributes;
import org.junit.Test;

import java.io.File;

public class PdbAnalysisTest {
    @Test
    //@Ignore("For make this work, there application initialization needed. This seems to be a lot of work to make it properly")
    public void validateParsingEmptyPdb() throws Exception {
        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(classLoader.getResource("empty.xml").getFile());

        PdbParserNEW parser = new PdbParserNEW(
                file, null, null,
                new PdbProgramAttributes("2D0C13AA-D03A-44C2-B13A-3C9077EEC622", "1", false, false, "sig", "f", "exe"), true);

        parser.parse();
    }
}
