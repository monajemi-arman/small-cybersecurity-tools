import pyshark
import sys

def extract_mssql_queries(pcap_file):
    try:
        capture = pyshark.FileCapture(pcap_file, display_filter="tds.query")
        queries = []

        for packet in capture:
            if 'tds' in packet:
                try:
                    query = packet.tds.query
                    queries.append(query)
                except AttributeError:
                    continue

        capture.close()
        return queries

    except Exception as e:
        print("Error reading file:", e)
        return []

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python extract_queries.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    mssql_queries = extract_mssql_queries(pcap_file)
    
    if mssql_queries:
        for idx, query in enumerate(mssql_queries, 1):
            print(f"-- Query {idx}\n{query}")
    else:
        print("No MSSQL queries found in the file.")
