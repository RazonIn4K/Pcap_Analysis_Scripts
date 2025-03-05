import concurrent.futures
import logging
from functools import partial

logger = logging.getLogger(__name__)

def run_parallel_analysis(pcap_file, analysis_functions, time_filter="", max_workers=None):
    """
    Run multiple analysis functions in parallel to improve performance.
    
    Args:
        pcap_file (str): Path to the PCAP file
        analysis_functions (list): List of analysis functions to run
        time_filter (str): Time filter to apply
        max_workers (int, optional): Maximum number of worker threads
        
    Returns:
        dict: Combined results from all analysis functions
    """
    results = {}
    
    # Create partial functions with fixed arguments
    tasks = []
    for func in analysis_functions:
        if func.__name__ == 'detect_dns_tunneling':
            # Special case for functions with additional parameters
            task = partial(func, pcap_file, 0.8, time_filter)
        else:
            task = partial(func, pcap_file, time_filter)
        tasks.append((func.__name__, task))
    
    # Execute tasks in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_name = {executor.submit(task): name for name, task in tasks}
        
        for future in concurrent.futures.as_completed(future_to_name):
            name = future_to_name[future]
            try:
                result = future.result()
                if result:
                    results[name] = result
            except Exception as e:
                logger.exception(f"Error in {name}: {e}")
    
    return results
