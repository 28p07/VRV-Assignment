import csv
import re
from collections import Counter

# Configurable threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

def parse_log(file_path):
    """Read log file and return all entries."""
    with open(file_path, 'r') as file:
        return file.readlines()

def extract_ip_counts(log_entries):
    """Count the number of requests per IP address."""
    ip_counts = Counter()
    for line in log_entries:
        ip_match = re.match(r'^([\d\.]+)', line)
        if ip_match:
            ip_counts[ip_match.group(1)] += 1
    return ip_counts

def find_top_endpoint(log_entries):
    """Identify the most frequently accessed endpoint."""
    endpoint_counts = Counter()
    for line in log_entries:
        endpoint_match = re.search(r'\"[A-Z]+ (/\S*)', line)
        if endpoint_match:
            endpoint_counts[endpoint_match.group(1)] += 1
    return endpoint_counts.most_common(1)[0] if endpoint_counts else ("N/A", 0)

def detect_brute_force(log_entries):
    """Find IPs with failed login attempts exceeding a threshold."""
    failed_attempts = Counter()
    for line in log_entries:
        if "401" in line or "Invalid credentials" in line:
            ip_match = re.match(r'^([\d\.]+)', line)
            if ip_match:
                failed_attempts[ip_match.group(1)] += 1
    return {ip: count for ip, count in failed_attempts.items() if count > FAILED_LOGIN_THRESHOLD}

def save_to_csv(ip_counts, top_endpoint, suspicious_ips, file_name="log_analysis_results.csv"):
    """Write analysis results to a CSV file."""
    with open(file_name, 'w', newline='') as file:
        writer = csv.writer(file)

        # Write IP request counts
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])

        writer.writerow([])  # Separator row

        # Write most accessed endpoint
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(top_endpoint)

        writer.writerow([])

        # Write suspicious activity
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def print_results(ip_counts, top_endpoint, suspicious_ips):
    """Display results in the terminal."""
    print("IP Address           Request Count")
    for ip, count in ip_counts.items():
        print(f"{ip:<20}{count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{top_endpoint[0]} (Accessed {top_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20}{count}")
    else:
        print("No suspicious activity detected.")

def main():
    log_file = "sample.log"  # Log file path
    log_entries = parse_log(log_file)

    ip_counts = extract_ip_counts(log_entries)
    top_endpoint = find_top_endpoint(log_entries)
    suspicious_ips = detect_brute_force(log_entries)

    print_results(ip_counts, top_endpoint, suspicious_ips)
    save_to_csv(ip_counts, top_endpoint, suspicious_ips)
    print("\nResults saved to log_analysis_results.csv")

if __name__ == "__main__":
    main()
