from src.backpork.core import BackporkEngine

def get_backpork_pairs():
    return [{"id": i, "label": f"Pair {i}"} for i in range(1, 11)]

def get_backpork_config():
    return BackporkEngine.load_config()

def save_backpork_config(data):
    BackporkEngine.save_config(data)
    return {"success": True}

def run_backpork_stream(data):
    return BackporkEngine.run_process(data)
