# Sample file with security issues for semgrep testing

def dangerous_function(user_input):
    """
    This function is dangerous because it uses eval on user input
    """
    result = eval(user_input)  # This should be detected by semgrep
    return result

def process_command(cmd):
    """
    This function executes a command from user input
    """
    import os
    os.system(cmd)  # This could be a command injection vulnerability
    
# Hardcoded credentials
API_KEY = "sk_live_1234567890abcdefghijklmnopqrstuvwxyz"
PASSWORD = "super_secret_password123"

# User input processing
user_data = input("Enter data: ")
processed = dangerous_function(user_data)