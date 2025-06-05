import csv
import os
import requests
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime
from matplotlib.ticker import MultipleLocator

def read_csv(path):
    data = {}
    with open(path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if row[0].isdigit():
                timestamp = int(row[1])
                price = float(row[2])
                data[timestamp] = price
    return data

def fetch_prices(timestamp, api_key):
    url = "https://min-api.cryptocompare.com/data/v2/histominute"
    params = {
        'fsym': 'ETH',
        'tsym': 'USDT',
        'toTs': timestamp,
        'limit': 1,
    }
    
    response = requests.get(url, params=params)
    if response.status_code == 200:
        data = response.json()
        data_len = len(data['Data']['Data'])
        last_item = data['Data']['Data'][data_len - 1]
        if data['Response'] == 'Success' and data_len > 0:
            if timestamp - last_item['time'] <= 60:
                # allowing one min diff
                return data['Data']['Data'][0]['close']
            else:
                return 0
def main():
    csv_data = read_csv('uni_prices.csv')
    
    timestamps = []
    csv_prices = []
    api_prices = []
    
    for ts, price in csv_data.items():
        api_price = fetch_prices(ts, api_key)
        if api_price:
            timestamps.append(ts)
            csv_prices.append(price)
            api_prices.append(api_price)
    
    print(timestamps);
    print(csv_prices);
    print(api_prices);

    # timestamps = [1749105683, 1749102011, 1749098375, 1749094775, 1749091175, 1749087551, 1749083951, 1749080363, 1749076763, 1749073079, 1749069491, 1749065879, 1749062255, 1749058619, 1749055019, 1749051419, 1749047807, 1749044183, 1749040559, 1749036923, 1749033275, 1749029675, 1749026075, 1749022427, 1749018779, 1749015179, 1749011567, 1749007979, 1749004343, 1749000731, 1748997119, 1748993519, 1748989919, 1748986259, 1748982671, 1748979047, 1748975447, 1748971847, 1748968247, 1748964647, 1748961035, 1748957387, 1748953775, 1748950187, 1748946587, 1748942951, 1748939291, 1748935667, 1748932055, 1748928443]
    # csv_prices = [2609.8080762655322, 2621.480490403204, 2624.393160328884, 2622.7686279534264, 2619.7231588548534, 2610.3963278671695, 2609.545936613066, 2608.729875162142, 2614.1021109699313, 2612.849426415079, 2609.528150105592, 2629.978419276374, 2639.693585306237, 2641.1199286093947, 2651.1515553967374, 2653.429993570316, 2610.912013801284, 2616.554217935566, 2623.7705098568176, 2634.658956898744, 2640.6144521020756, 2634.892883303356, 2637.2214214676064, 2626.727496929253, 2620.77461018866, 2628.379186142654, 2631.9788198198744, 2635.816798914804, 2617.5044214035506, 2610.3798778314335, 2595.2227034083376, 2600.5514233505082, 2595.497388260199, 2608.125684065392, 2605.341895595558, 2620.625110387102, 2614.4468008942767, 2620.2157734437033, 2616.703457689552, 2643.3060943956352, 2628.4498082456616, 2620.172618189739, 2603.6126702299416, 2613.240784817929, 2612.434634630224, 2601.7559333260524, 2601.6135961284067, 2613.2477388445636, 2612.322965102058, 2599.466433363167]
    # api_prices = [2611.79, 2615.1, 2630.77, 2629.6, 2627.53, 2606.69, 2612.21, 2609.82, 2612.91, 2618.81, 2610.49, 2626.76, 2636.21, 2638.42, 2655.51, 2648.87, 2614.97, 2621.86, 2622.5, 2627.96, 2636.65, 2632.8, 2639.91, 2627.62, 2624.14, 2621.03, 2625.66, 2634.53, 2614.45, 2612.09, 2589.82, 2595.93, 2600.22, 2611.75, 2598.33, 2626.38, 2614.02, 2623.73, 2610.51, 2642.56, 2632.72, 2621.35, 2608.12, 2607.72, 2616.27, 2601.82, 2604.33, 2609.74, 2604.84, 2600.63]
    dates = [datetime.fromtimestamp(ts) for ts in timestamps]

    plt.figure(figsize=(14, 7))

    # Plot with different colors and markers
    plt.plot(dates, csv_prices, label='UNI Price', marker='o', color='blue', markersize=5)
    plt.plot(dates, api_prices, label='API Price', marker='x', color='green', markersize=5)

    plt.title('ETH Price Comparison: UNI vs API', fontsize=14)
    plt.xlabel('Time', fontsize=12)
    plt.ylabel('Price (USD)', fontsize=12)
    plt.legend(fontsize=12)
    
    # Add more grid lines
    plt.grid(True, which='both', ls='-', alpha=0.5)
    
    ax = plt.gca()

    # X-axis: grid/ticks every 30 minutes
    ax.xaxis.set_major_locator(mdates.HourLocator(interval=2))
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%m-%d %H:%M'))

    # Y-axis: grid/ticks every $1
    ax.yaxis.set_major_locator(MultipleLocator(2))
    ax.yaxis.set_minor_locator(MultipleLocator(2))

    # Grid lines
    ax.grid(which='major', axis='both', linestyle='-', alpha=0.7)
    ax.grid(which='minor', axis='both', linestyle=':', alpha=0.4)

    plt.gcf().autofmt_xdate()

    plt.show()
if __name__ == "__main__":
    main()
