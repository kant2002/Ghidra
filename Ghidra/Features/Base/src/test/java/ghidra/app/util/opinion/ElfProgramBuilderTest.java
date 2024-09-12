package ghidra.app.util.opinion;

import generic.continues.GenericFactory;
import generic.continues.RethrowContinuesFactory;
import generic.jar.ResourceFile;
import ghidra.GhidraApplicationLayout;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.RandomAccessByteProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class ElfProgramBuilderTest {

    @Test
    public void readingElfHeader() throws Exception {
        ApplicationConfiguration configuration = new ApplicationConfiguration();
        configuration.setInitializeLogging(false);
        Application.initializeApplication(
            new GhidraApplicationLayout(new File("../../..")),
            configuration);
        UniversalIdGenerator.initialize();

        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(classLoader.getResource("elf/orc_0013").getFile());
        ByteProvider provider = new RandomAccessByteProvider(file);
        GenericFactory factory = RethrowContinuesFactory.INSTANCE;
        ElfHeader elf = ElfHeader.createElfHeader(factory, provider);
        List<Option> options = new ArrayList<Option>();
        MessageLog log = new MessageLog();
        LanguageCompilerSpecPair specPair = new LanguageCompilerSpecPair("x86:LE:64:default", "gcc");
        LanguageService languageService = DefaultLanguageService.getLanguageService(
                new ResourceFile(new File(
                        "../../Processors/x86/data/languages/x86.ldefs")));
        Language language = languageService.getLanguage(specPair.languageID);
        CompilerSpec compilerSpec = language.getCompilerSpecByID(specPair.compilerSpecID);
        Object consumer = new Object();
        Program prog = new ProgramDB("orc_0013", language, compilerSpec, consumer);
        ElfProgramBuilder.loadElf(elf, prog, options, log, MemoryConflictHandler.ALWAYS_OVERWRITE, TaskMonitor.DUMMY);
    }

    @Test
    public void readingElfHeader2() throws Exception {
        ApplicationConfiguration configuration = new ApplicationConfiguration();
        configuration.setInitializeLogging(false);
        Application.initializeApplication(
                new GhidraApplicationLayout(new File("../../..")),
                configuration);
        UniversalIdGenerator.initialize();

        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(classLoader.getResource("elf/orc_0001").getFile());
        ByteProvider provider = new RandomAccessByteProvider(file);
        GenericFactory factory = RethrowContinuesFactory.INSTANCE;
        ElfHeader elf = ElfHeader.createElfHeader(factory, provider);
        List<Option> options = new ArrayList<Option>();
        MessageLog log = new MessageLog();
        LanguageCompilerSpecPair specPair = new LanguageCompilerSpecPair("x86:LE:64:default", "gcc");
        LanguageService languageService = DefaultLanguageService.getLanguageService(
                new ResourceFile(new File(
                        "../../Processors/x86/data/languages/x86.ldefs")));
        Language language = languageService.getLanguage(specPair.languageID);
        CompilerSpec compilerSpec = language.getCompilerSpecByID(specPair.compilerSpecID);
        Object consumer = new Object();
        Program prog = new ProgramDB("orc_0013", language, compilerSpec, consumer);
        ElfProgramBuilder.loadElf(elf, prog, options, log, MemoryConflictHandler.ALWAYS_OVERWRITE, TaskMonitor.DUMMY);
    }
}