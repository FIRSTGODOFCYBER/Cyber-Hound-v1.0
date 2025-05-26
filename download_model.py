import gdown

url = "https://drive.google.com/uc?id=1RZPBQFDVD6GIBcml2cd1ylvp0mG3VKyA"
output = "randomforest_model.joblib"

print("Downloading model file...")
gdown.download(url, output, quiet=False)
print("Download completed!")
