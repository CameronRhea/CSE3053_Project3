import string
import random
import sys

def generate_in_files(networks, nodes):
    for i in range(1, networks+1):
        for j in range(1,nodes+1):
            rand_netw1 = random.randint(1,networks)
            rand_node1 = random.randint(1,nodes)
            rand_string1 = ''.join(random.choices(string.ascii_letters, k=7))

            rand_netw2 = random.randint(1,networks)
            rand_node2 = random.randint(1,nodes)
            rand_string2 = ''.join(random.choices(string.ascii_letters, k=7))

            lines = f'{rand_netw1}_{rand_node1}:{rand_string1}\n{rand_netw2}_{rand_node2}:{rand_string2}'
        
            with open(f'in/node{i}_{j}.txt', 'w') as f:
                f.write(lines)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python in_files_generator.py <number_of_networks> <number_of_nodes_per_network>")
        sys.exit(1)
    
    try:
        num_nets = int(sys.argv[1])
        num_nodes = int(sys.argv[2])
        if not (2 <= num_nets <= 16):
            raise ValueError("Number of files must be between 2 and 16 and match number of nodes")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    generate_in_files(num_nets, num_nodes)