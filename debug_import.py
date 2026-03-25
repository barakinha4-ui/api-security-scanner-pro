try:
    import app
    print("Import OK")
except Exception:
    import traceback
    traceback.print_exc()
