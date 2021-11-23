#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

pub trait OutputExt {
    fn info(&self) -> String;
}

impl OutputExt for std::process::Output {
    fn info(&self) -> String {
        let mut out = String::new();

        #[cfg(unix)]
        if let Some(signal) = self.status.signal() {
            out += &format!("killed by signal {}", signal);
        }

        if let Some(code) = self.status.code() {
            if !out.is_empty() {
                out += ", ";
            }
            out += &format!("exit code {}", code);
        }

        /*
         * Attempt to render stderr from the command:
         */
        let stderr = String::from_utf8_lossy(&self.stderr).trim().to_string();
        let extra = if stderr.is_empty() {
            /*
             * If there is no stderr output, this command might emit its
             * failure message on stdout:
             */
            String::from_utf8_lossy(&self.stdout).trim().to_string()
        } else {
            stderr
        };

        if !extra.is_empty() {
            if !out.is_empty() {
                out += ": ";
            }
            out += &extra;
        }

        out
    }
}
