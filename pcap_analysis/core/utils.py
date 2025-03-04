#!/usr/bin/env python3
import math
import os

def calculate_entropy(string):
    """Calculate Shannon entropy of a string - useful for DGA detection"""
    if not string:
        return 0
        
    prob = {}
    for char in string:
        if char in prob:
            prob[char] += 1
        else:
            prob[char] = 1
    
    entropy = 0
    for char in prob:
        p = prob[char] / len(string)
        entropy -= p * (math.log(p) / math.log(2))
    
    return entropy

def ensure_dir(directory):
    """Ensure a directory exists, creating it if necessary"""
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"Created directory: {directory}")
    return directory

def format_time_filter(start_time=None, end_time=None):
    """Format a time filter string for tshark commands"""
    time_filter = ""
    if start_time and end_time:
        time_filter = f" and (frame.time >= \"{start_time}\" and frame.time <= \"{end_time}\")"
    return time_filter 