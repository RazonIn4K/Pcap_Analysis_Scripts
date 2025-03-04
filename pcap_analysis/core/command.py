#!/usr/bin/env python3
import subprocess
import sys

# Global cache for command results
command_cache = {}

def run_command(command, use_cache=True):
    """Execute a shell command and return its output with progress indicator"""
    if use_cache and command in command_cache:
        return command_cache[command]
        
    try:
        print("Running analysis...", end="\r")
        sys.stdout.flush()  # Ensure the progress indicator is displayed immediately
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        print("                    ", end="\r")  # Clear the line
        if process.returncode != 0:
            print(f"Error running command: {stderr.decode('utf-8')}")
            return None
        result = stdout.decode('utf-8')
        
        if use_cache:
            command_cache[command] = result
        return result
    except Exception as e:
        print(f"Exception while running command: {e}")
        return None

def clear_cache():
    """Clear the command cache"""
    global command_cache
    command_cache = {} 