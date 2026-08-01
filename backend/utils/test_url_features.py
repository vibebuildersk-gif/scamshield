from url_features import extract_url_features

url = input("Enter URL: ")

features = extract_url_features(url)

print("\nExtracted Features\n")

for key, value in features.items():
    print(f"{key:30} : {value}")