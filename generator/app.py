from fastapi import FastAPI
import generator

app = FastAPI(title="Data Generator Service")

@app.post("/generate")
def generate_data():
    return generator.generate_data()

@app.delete("/clear")
def clear_data():
    return generator.clear_all_stores()

@app.get("/status")
def get_status():
    return generator.get_status()

@app.get("/groups")
def list_groups():
    return generator.list_groups()

@app.get("/")
def root():
    return {"service": "generator", "description": "Data generation service"}
