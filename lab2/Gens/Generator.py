import random

def generate_sequence(length):
    """Генерирует ПСП"""
    return ''.join(str(random.getrandbits(1)) for _ in range(length))


if __name__ == '__main__':
    seq = generate_sequence(10000)
    with open("..\sequences\sequence_py.txt", "w") as f:
        f.write(seq)
    print("ok")