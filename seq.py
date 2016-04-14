#!/usr/bin/python3

current = 0x80000000
def assign_seq(message=None):
    global current
    ret = current
    current += 1
    return ret

if __name__ == '__main__':
    print(assign_seq())
    print(assign_seq())
    print(assign_seq())
    

