package org.keepassxc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

public class KindOfKeePassXC {
    private static final Logger LOG = LoggerFactory.getLogger(KindOfKeePassXC.class);

    public static Optional<KeePassXCType> determineType() {
        ///home/<user>/Downloads/KeePassXC-2.7.4-x86_64.AppImage
        var processHandle = ProcessHandle.allProcesses()
                .filter(ph -> ph.info().command().isPresent() && ph.info().command().get().contains("KeePassXC")
                        && ph.info().command().get().contains("AppImage"))
                .findFirst();

        if (processHandle.isPresent()) {
            LOG.debug("Found running KeePassXC AppImage");
            return Optional.of(KeePassXCType.AppImage);
        }

        ///usr/bin/bwrap --args 38 keepassxc-wrapper
        processHandle = ProcessHandle.allProcesses()
                .filter(ph -> ph.info().commandLine().isPresent() && ph.info().commandLine().get().contains("keepassxc")
                        && ph.info().commandLine().get().contains("bwrap"))
                .findFirst();

        if (processHandle.isPresent()) {
            LOG.debug("Found running KeePassXC installed via Flatpak");
            return Optional.of(KeePassXCType.Flatpak);
        }

        ///snap/keepassxc/1645/usr/bin/keepassxc
        processHandle = ProcessHandle.allProcesses()
                .filter(ph -> ph.info().commandLine().isPresent() && ph.info().commandLine().get().contains("keepassxc")
                        && ph.info().commandLine().get().contains("snap"))
                .findFirst();

        if (processHandle.isPresent())  {
            LOG.debug("Found running KeePassXC installed via Snap");
            return Optional.of(KeePassXCType.Snap);
        }

        ///usr/bin/keepassxc, gets started as "keepassxc"
        processHandle = ProcessHandle.allProcesses()
                .filter(ph -> ph.info().commandLine().isPresent() && ph.info().commandLine().get().contains("keepassxc"))
                .findFirst();

        if (processHandle.isPresent()) {
            LOG.debug("Found running KeePassXC installed from repository");
            return Optional.of(KeePassXCType.Repo);
        }

        LOG.debug("Could not find running KeePassXC application");
        return Optional.empty();
    }
}
