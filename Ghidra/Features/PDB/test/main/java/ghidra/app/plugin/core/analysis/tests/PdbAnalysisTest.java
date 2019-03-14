package ghidra.app.plugin.core.analysis.tests;

import ghidra.app.util.bin.format.pdb.PdbParserNEW;
import ghidra.app.util.bin.format.pdb.PdbProgramAttributes;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import java.io.File;

public class PdbAnalysisTest {
    @Test
    public void validateParsingEmptyPdbDoesNotCrash() throws Exception {
        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(classLoader.getResource("empty.xml").getFile());

        PdbParserNEW parser = new PdbParserNEW(
                file, null, null,
                new PdbProgramAttributes("2D0C13AA-D03A-44C2-B13A-3C9077EEC622", "1", false, false, "sig", "f", "exe"), true);

        parser.parse();
    }

    @Test
    public void validateApplyEmptyPdbDoesNotCrash() throws Exception {
        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(classLoader.getResource("empty.xml").getFile());

        UniversalIdGenerator.initialize();

        PdbParserNEW parser = new PdbParserNEW(
                file, new FakeProgram(), null,
                new PdbProgramAttributes("2D0C13AA-D03A-44C2-B13A-3C9077EEC622", "1", false, false, "sig", "f", "exe"), true);

        parser.parse();
        //parser.openDataTypeArchives();
        parser.applyTo(TaskMonitor.DUMMY, null);
    }
}
