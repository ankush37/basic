import pickle

class Node:
    def __init__(self, key, value):
        self.key = key
        self.value = value
        self.prev = None
        self.next = None

class LRUCache:
    def __init__(self, capacity):
        self.capacity = capacity
        self.cache = {}
        self.head = Node(None, None)  # Dummy head node
        self.tail = Node(None, None)  # Dummy tail node
        self.head.next = self.tail
        self.tail.prev = self.head

    def _remove_node(self, node):
        # Remove a node from the linked list
        node.prev.next = node.next
        node.next.prev = node.prev

    def _add_to_head(self, node):
        # Add a node to the head of the linked list
        node.next = self.head.next
        node.prev = self.head
        self.head.next.prev = node
        self.head.next = node

    def get(self, key):
        if key in self.cache:
            node = self.cache[key]
            # Move the accessed key to the head to mark it as most recently used
            self._remove_node(node)
            self._add_to_head(node)
            return node.value
        else:
            return None

    def put(self, key, value):
        if key in self.cache:
            # If the key is already present, update the value and move it to the head
            node = self.cache[key]
            node.value = value
            self._remove_node(node)
            self._add_to_head(node)
        else:
            # If the cache is full, remove the least recently used item from the tail
            if len(self.cache) >= self.capacity:
                lru_node = self.tail.prev
                self._remove_node(lru_node)
                del self.cache[lru_node.key]

            # Add the new key-value pair to the cache and the head of the linked list
            new_node = Node(key, value)
            self.cache[key] = new_node
            self._add_to_head(new_node)

    def print_cache(self):
        current = self.head.next
        while current != self.tail:
            print((current.key, current.value), end=" ")
            current = current.next
        print()

    def save_to_file(self, filename):
        with open(filename, 'wb') as file:
            pickle.dump(self.cache, file)

    def load_from_file(self, filename):
        try:
            with open(filename, 'rb') as file:
                self.cache = pickle.load(file)
        except FileNotFoundError:
            # Handle the case where the file does not exist (initial startup)
            pass
 