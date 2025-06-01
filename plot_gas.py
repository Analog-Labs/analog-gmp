import csv
import matplotlib.pyplot as plt


def read_csv(path):
    data = {}
    with open(path, 'r') as f:
        r = csv.reader(f)
        r.__next__()
        for row in r:
            data[int(row[0])] = (int(row[1]), int(row[2]), int(row[3]))
        data = dict(sorted(data.items()))
    x, y0, y1, y2 = [], [], [], []
    for (k, (v0, v1, v2)) in data.items():
        x.append(k)
        y0.append(v0)
        y1.append(v1)
        y2.append(v2)
    return (x, y0, y1, y2)


def coeffs(x, y):
    c1 = (y[-1] - y[0]) / (x[-1] - x[0])
    c0 = y[0] - c1 * x[0]
    return (c0, c1)


def plot(c0, c1, max_x):
    xp = [x in range(0, max_x, 100)]
    yp = [c1 * x + c0 for x in xp]
    plt.plot(xp, yp)


msg_size, exec, reimb, base = read_csv('gas.csv')
#print(msg_size, exec, reimb, base)
c_exec = coeffs(msg_size, exec)
c_reimb = coeffs(msg_size, reimb)
c_base = coeffs(msg_size, base)
print('exec', c_exec[0], '+', c_exec[1], '*', 'msg_size', '+', 'gas_limit')
print('reimb', c_reimb[0], '+', c_reimb[1], '*', 'msg_size')
print('base', c_base[0], '+', c_base[1], '*', 'msg_size')

c0 = c_base[0] + c_reimb[0]
c1 = c_base[1] + c_exec[1]
cd = c_exec[0] - c_reimb[0]
print('c0', c0)
print('c1', c1)
print('cd', cd)

def msg_gas(sessions, msg_size, gas_limit):
    return (c1 * msg_size + c0) * sessions + cd + gas_limit

print('gas', 's', 1, 'x', 0, 'l', 0, msg_gas(1, 0, 0))
print('gas', 's', 2, 'x', 0, 'l', 0, msg_gas(2, 0, 0))
print('gas', 's', 3, 'x', 32, 'l', 5000, msg_gas(3, 32, 5000))
#plt.show()
