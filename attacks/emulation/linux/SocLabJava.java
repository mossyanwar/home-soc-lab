// home-soc-lab: benign JVM emulation for Linux rows L1 and L4.
//
// Run on UBU-SRV01 in the lab (Java 11+ can run a single file directly):
//     java SocLabJava.java
//
// L1 (T1190 / T1059.004): the JVM starts a child shell, which is the signal the
// rule lnx_proc_shell_spawned_by_java looks for (a shell whose parent is java,
// as happens when a web app is exploited). The shell only prints a line.
//
// L4 (T1505.003): the JVM writes a .jsp file under a webapps-style directory,
// which is the signal the rule lnx_file_jsp_written_by_java looks for. The file
// content is an inert comment, not a working web shell.
//
// Both are reverted: the temp webapps directory is deleted on exit. Not run in
// this repo.

import java.io.IOException;
import java.nio.file.*;

public class SocLabJava {
    public static void main(String[] args) throws IOException, InterruptedException {
        // L1: java spawns a shell.
        Process p = new ProcessBuilder("/bin/bash", "-c", "echo soclab-L1").inheritIO().start();
        p.waitFor();

        // L4: java writes a .jsp into a webapps-style path.
        Path webapps = Files.createTempDirectory("soclab-webapps-");
        Path root = Files.createDirectories(webapps.resolve("ROOT"));
        Path jsp = root.resolve("soclab.jsp");
        Files.writeString(jsp, "<%-- soclab L4 emulation, inert, not a web shell --%>\n");
        System.out.println("soclab-L4 wrote " + jsp);

        Thread.sleep(1000);

        // revert
        Files.deleteIfExists(jsp);
        Files.deleteIfExists(root);
        Files.deleteIfExists(webapps);
    }
}
