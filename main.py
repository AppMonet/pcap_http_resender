import time

from scapy.all import rdpcap
from scapy.layers import http
import requests
from concurrent.futures import ThreadPoolExecutor

from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import Ether

from thread_safe_counter import ThreadSafeCounter

# Default application variables
DEFAULT_ENDPOINT = 'localhost:80'
DEFAULT_NUM_OF_THREADS = 100
DEFAULT_NUM_OF_REQUESTS = 1000
DEFAULT_PCAP_PATH = 'data.pcap'


def send_packet(packet, endpoint, counter):
    try:
        if packet.haslayer(http.HTTPRequest):
            http_layer = packet.getlayer(http.HTTPRequest)

            new_packet = Ether() / IP() / TCP() / http_layer
            req = new_packet[http.HTTPRequest]

            path = req.Path.decode()
            headers = req.fields
            decoded_headers = decode_headers(headers)
            body = req.load
            method = req.Method
            url = endpoint + path

            # send request
            response = requests.request(method, url, data=body, headers=decoded_headers)
            print(f"Sent request to {url}. Response: {response.status_code}")
            counter.increment()

    except Exception as e:
        print(f"Error: {e}")


def decode_headers(headers):
    updated_headers = {}

    for key, value in headers.items():
        if isinstance(key, bytes):
            key = key.decode()

        if isinstance(value, bytes):
            value = value.decode()

        updated_key = key.replace('_', '-')
        updated_headers[updated_key] = value

    return updated_headers

def send_requests(endpoint, num_of_threads, pcap):
    counter = ThreadSafeCounter()

    start_time = time.time()
    with ThreadPoolExecutor(max_workers=num_of_threads) as executor:
        futures = [executor.submit(send_packet, packet, endpoint, counter) for packet in pcap]

        for future in futures:
            future.result()
    end_time = time.time()

    print("\n---------------------")
    print("DONE!")
    print(f"\nSent {counter.value()} requests in {end_time - start_time} seconds")
    print(f"Requests per second: {counter.value() / (end_time - start_time)}")


def load_pcap(pcap_path):
    print('\nLoading packets from PCAP file...')
    pcap = rdpcap(pcap_path)
    print(f"Loaded {len(pcap)} packets")
    return pcap


def run_program(endpoint, num_threads, pcap):
    print('Sending requests..')
    send_requests(endpoint, num_threads, pcap)

    run_again = input("\nDo you want to run the program again? (Y/n): ") or "y"

    if run_again.lower() == "y" or run_again.lower() == "yes" or run_again == "Y":
        run_program(endpoint, num_threads, pcap)


def load_values():
    endpoint = input(f"Enter the endpoint (default: {DEFAULT_ENDPOINT}): ") or DEFAULT_ENDPOINT
    pcap_path = input(f"Enter the path to the pcap file (default: {DEFAULT_PCAP_PATH}): ") or DEFAULT_PCAP_PATH
    num_threads = int(input(
        f"Enter the number of concurrent threads (default: {DEFAULT_NUM_OF_THREADS}): ") or DEFAULT_NUM_OF_THREADS)

    num_threads = abs(num_threads)
    return endpoint, num_threads, pcap_path


if __name__ == '__main__':
    print("Welcome to the pcap sender!")
    print("---------------------\n")
    endpoint, num_threads, pcap_path = load_values()
    pcap = load_pcap(pcap_path)
    run_program(endpoint, num_threads, pcap)
