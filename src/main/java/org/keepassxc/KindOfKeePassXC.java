package org.keepassxc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

public class KindOfKeePassXC {
    private static final Logger LOG = LoggerFactory.getLogger(KindOfKeePassXC.class);

    static Optional<KeePassXCType> determineType() {
        var processHandle = ProcessHandle.allProcesses()
                .filter(ph -> ph.info().command().isPresent() && ph.info().command().get().contains("KeePassXC"))
                .findFirst();
        if (processHandle.isPresent() && processHandle.get().info().command().get().contains("AppImage")) {
            LOG.debug("Found running KeePassXC AppImage");
            return Optional.of(KeePassXCType.AppImage);
        }

        processHandle = ProcessHandle.allProcesses()
                .filter(ph -> ph.info().commandLine().isPresent() && ph.info().commandLine().get().contains("keepassxc"))
                .findFirst();
        if (processHandle.isPresent()) {
            LOG.debug("Found running KeePassXC installed from repository");
            return Optional.of(KeePassXCType.Repo);
        }

        processHandle = ProcessHandle.allProcesses()
                .filter(ph -> ph.info().command().isPresent() && ph.info().command().get().contains("keepassxc"))
                .findFirst();
        if (processHandle.isPresent() && processHandle.get().info().command().get().contains("app")) {
            LOG.debug("Found running KeePassXC installed via Flatpak");
            return Optional.of(KeePassXCType.Flatpak);
        }

        if (processHandle.isPresent() && processHandle.get().info().command().get().contains("snap")) {
            LOG.debug("Found running KeePassXC installed via Snap");
            return Optional.of(KeePassXCType.Snap);
        }

        LOG.debug("Could not find running KeePassXC application");
        return Optional.empty();
    }
}
