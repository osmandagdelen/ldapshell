import time
import ssl
import os
from ldap3 import Server, ALL, Connection, NTLM, SUBTREE, Tls, MODIFY_ADD, MODIFY_REPLACE, SASL, KERBEROS
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID, ACE, ACCESS_ALLOWED_ACE, ACCESS_MASK
from rich import print
import readline
import rlcompleter
import atexit
import heapq
import shlex

class Session:
    def __init__(self):
        self.items = []

    def push(self, item):
        self.items.append(item)

    def pop(self):
        """when its empty"""
        if self.is_empty():
            raise IndexError("no history yet :(")
        return self.items.pop()
    def peek(self):
        if self.is_empty():
            raise IndexError("*")
        return self.items[-1]
    def is_empty(self):
        return len(self.items) == 0

    def size(self):
        return len(self.items)

    def show_all(self):
        print("[bold magenta]--- Query History ---[/bold magenta]")
        for i, item in enumerate(self.items, 1):
            print(f"{i}. {item}")

    def __str__(self):
        return f"Session({self.items})"
class Queue:
    def __init__(self):
        self.items = []
    def enqueue(self, item):
        self.items.append(item)
    def dequeue(self):
        if self.is_empty():
            raise IndexError("Queue empty")
        return self.items.pop(0)
    def is_empty(self):
        return len(self.items) == 0
    def size(self):
        return len(self.items)
class DecisionNode:
    def __init__(self, question, left=None, right=None):
        self.question = question
        self.left = left
        self.right = right
class TreeNode:
    def __init__(self, value):
        self.value = value
        self.children = []
class HistoryNode:
    def __init__(self, data):
        self.data = data
        self.next = None
class SinglyLinkedList:
    def __init__(self):
        self.head = None
        self.size = 0
    def is_empty(self):
        return self.head is None
    def get_size(self):
        return self.size

    def add(self, data):
        new_node = HistoryNode(data)
        if not self.head:
            self.head = new_node
            self.tail = new_node
        else:
            self.tail.next = new_node
            self.tail = new_node
        self.size += 1

    def insert_at_beginning(self, data):

        new_node = HistoryNode(data)
        new_node.next = self.head
        self.head = new_node
        self.size += 1

    def insert_at_end(self, data):
        new_node = HistoryNode(data)

        if self.is_empty():
            self.head = new_node
        else:
            current = self.head
            while current.next:
                current = current.next
            current.next = new_node
        self.size += 1

    def insert_at_position(self, data, position):

        if position < 0 or position > self.size:
            raise IndexError("Position out of range")
        if position == 0:
            self.insert_at_beginning(data)
            return
        new_node = HistoryNode(data)
        current = self.head

        for _ in range(position -1):
            current = current.next

        new_node.next = current.next
        current.next = new_node
        self.size += 1

    def delete_all_beginning(self):

        if self.is_empty():
            raise IndexError("List is empty")

        data = self.head.data
        self.head = self.head.next
        self.size -= 1
        return data
    def delete_at_end(self):
        if self.is_empty():
            raise IndexError("List is empty")

        if self.head.next is None:
            data = self.head.data
            self.head = None
            self.size -= 1
            return data
        current = self.head
        while current.next.next:
            current = current.next
        data = current.next.data
        current.next = None
        self.size -= 1
        return data
    def delete_by_value(self, value):
        if self.is_empty():
            raise IndexError("List is empty")

        if self.head.data == value:
            self.delete_all_beginning()
            return True

        current = self.head
        while current.next:
            if current.next.data == value:
                current.next = current.next.next
                self.size -= 1
                return True
            current = current.next
        return False

    def search(self, value):
        current = self.head
        position = 0

        while current:
            if current.data == value:
                return position
            current = current.next
            position += 1
        return -1

    def display(self):
        if self.is_empty():
            return "Empty List"

        current = self.head
        elements = []

        while current:
            elements.append(str(current.data))
            current = current.next

        return " -> ".join(elements) + " -> None"


    def show_all(self):
        print("[bold magenta]--- Query History ---[/bold magenta]")
        current = self.head
        count = 1
        while current:
            print(f"{count}. {current.data}")
            current = current.next
            count += 1

    def __str__(self):
        return self.display()
class SessionManager:
    def __init__(self, max_size=1000):
        self.queue = []
        self.max_size = max_size

    def add_session(self, profile):
        if len(self.queue) >= self.max_size:
            old_session = self.queue.pop(0)
            print(f"[bold red][!] Session limit reached. Disconnecting: {old_session['username']}[/bold red]")

        self.queue.append(profile)
        return len(self.queue) - 1
    def get_session(self, index):
        return self.queue[index]

class BSTNode:
    def __init__(self, username, data=None):
        self.key = username.lower()
        self.data = data
        self.left = None
        self.right = None
class UserCacheBST:
    def __init__(self):
        self.root = None

    def insert(self, username, data):
        if not self.root:
            self.root = BSTNode(username, data)
            return

        curr = self.root
        while True:
            if username.lower() < curr.key:
                if curr.left is None:
                    curr.left = BSTNode(username, data)
                    break
                curr = curr.left
            elif username.lower() > curr.key:
                if curr.right is None:
                    curr.right = BSTNode(username, data)
                    break
                curr = curr.right
            else:
                break

    def search(self, username):
        curr = self.root
        key = username.lower()
        while curr:
            if key == curr.key:
                return curr.data
            elif key < curr.key:
                curr = curr.left
            else:
                curr = curr.right
        return None



