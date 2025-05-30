import csv
import matplotlib.pyplot as plt

gas = {}
with open('output/gas.csv', 'r') as f:
    r = csv.reader(f)
    r.__next__()
    for row in r:
        gas[int(row[0])] = int(row[1])
gas = dict(sorted(gas.items()))
x, y = [], []
for (msgSize, gas) in gas.items():
    x.append(msgSize)
    y.append(gas)
plt.plot(x, y)

c1 = (y[-1] - y[0]) / (x[-1] - x[0])
c0 = y[0] - c1 * x[0]

xp = [x in range(0, x[-1], 100)]
yp = [c1 * x + c0 for x in xp]
plt.plot(xp, yp)

print('c0', c0)
print('c1', c1)

plt.show()
