import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib

# Save the trained model to a file



# Step 1: Load CSV file in chunks and process
chunk_size = 1000  # Adjust based on your available memory
chunks = pd.read_csv('E:\Vulnarabilities\vulnerability_scanner_web\Learning\nvdcve-1.1-2022.json', chunksize=chunk_size)

# Initialize an empty list to collect processed chunks
processed_chunks = []

# Process each chunk
for chunk in chunks:
    print("Columns in this chunk:", chunk.columns)  # Print the column names in the chunk

    # Flatten the 'CVE_Items' column (if necessary)
    if 'CVE_Items' in chunk.columns:
        chunk = pd.json_normalize(chunk['CVE_Items'], sep='_')  # Flatten the nested column

    print("Columns after flattening:", chunk.columns)  # Print columns after flattening

    # Here we use 'cwe_name' as the target variable (label)
    if 'cwe_name' in chunk.columns:  # Ensure 'cwe_name' is in the columns
        X = chunk.drop(columns=['cwe_name'])  # Features
        y = chunk['cwe_name']  # Label
    else:
        print("No 'cwe_name' column found. Please inspect the data.")
        break

    # Check that X and y have the same number of rows in each chunk
    if X.shape[0] != y.shape[0]:
        print(f"Mismatch in chunk sizes! X: {X.shape[0]}, y: {y.shape[0]}")
        break

    # Encode categorical features using LabelEncoder
    for column in X.select_dtypes(include=['object']).columns:
        le = LabelEncoder()
        X[column] = le.fit_transform(X[column].astype(str))

    # Optionally, if you have text columns, use TF-IDF Vectorizer to convert them to numerical form
    if 'summary' in X.columns:
        # Ensure all values in 'summary' are treated as strings
        X['summary'] = X['summary'].fillna('missing').astype(str)

        vectorizer = TfidfVectorizer(max_features=100)  # You can adjust 'max_features' based on your needs
        summary_tfidf = vectorizer.fit_transform(X['summary']).toarray()  # Transform summary column to numeric form

        X = X.drop(columns=['summary'])  # Drop the original text column
        X = pd.concat([X, pd.DataFrame(summary_tfidf)], axis=1)  # Add TF-IDF features to the DataFrame

    # Append the processed chunk
    processed_chunks.append((X, y))

# Combine all processed chunks into one DataFrame
X_all = pd.concat([x for x, y in processed_chunks], ignore_index=True)
y_all = pd.concat([y for x, y in processed_chunks], ignore_index=True)

# Verify the final shape of X_all and y_all
print(f"Final shape of X_all: {X_all.shape}, Final shape of y_all: {y_all.shape}")

# Ensure that the number of samples in X_all and y_all match
if X_all.shape[0] != y_all.shape[0]:
    print(f"Error: Mismatch in the number of rows between features (X_all) and labels (y_all).")
else:
    # Step 2: Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X_all, y_all, test_size=0.2, random_state=42)

    # Step 3: Train the model (Random Forest Classifier in this example)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Step 4: Make predictions and evaluate the model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {accuracy:.2f}")

joblib.dump(model, 'Rlearning.pkl')