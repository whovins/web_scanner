def f(x, acc=[]):
    acc.append(x)
    return acc

print(f(1))
print(f(2))
print(f(3, []))
print(f(4))