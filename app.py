from flask import Flask, render_template, request, jsonify
from script import host_up, scan_port, sniff_port

app = Flask(__name__)


@app.route('/')
def index():
    return render_template("index.html", host_up=host_up())


@app.route('/scan', methods=['GET'])
def scan_ports():
    min_p = request.args.get('minPort')
    max_p = request.args.get('maxPort')

    try:
        min_p = int(min_p)
        max_p = int(max_p)
    except TypeError:
        return jsonify({"Error": "Invalid"})

    if min_p < 0 or max_p < 0 or max_p < min_p:
        return jsonify({"Error": "Invalid"})

    open_ports = []
    if host_up():
        for p in range(int(min_p), int(max_p) + 1):
            port_open = scan_port(p)
            if port_open:
                open_ports.append(p)

    return jsonify(open_ports)


@app.route('/sniff', methods=['GET'])
def sniff():
    port = request.args.get('port')
    if not port:
        return jsonify({"Error": "Invalid"})
    packets = sniff_port(port, count=5, timeout=1)
    return jsonify(list(packets))

//ipgeolocation
@app.route('/getloc', methods=['GET'])
def getloc():
    ip= request.args.get('ip')
	if not ip:
		return jsonify({"Error": "Invalid"})
	r= requests.get('https://api.ipgeolocation.io/ipgeo?apiKey=2044304df1904a19b9b1119e2476b4b7&', +ip)
return jsonify(r)
	

  
	




if __name__ == '__main__':
    app.run()
