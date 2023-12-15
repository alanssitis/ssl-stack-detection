import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KNeighborsClassifier

def preprocess_ciphersuite(ciphersuite):
    return ciphersuite.replace('128', '').replace('256', '').replace('384', '')

df = pd.read_csv('../dataset.csv')
df = df.dropna()
unique_stacks = df['stack'].unique()

for stack_value in unique_stacks:
    stack_df = df[df['stack'] == stack_value]
    stack_df['ciphersuite'] = stack_df['ciphersuite'].apply(preprocess_ciphersuite)
    X = stack_df[['time']]
    y = stack_df['ciphersuite']

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

    n_neighbors = 100
    knn_model = KNeighborsClassifier(n_neighbors=n_neighbors)
    knn_model.fit(X_train, y_train)

    accuracy = knn_model.score(X_test, y_test)
    print(f'Model Accuracy on Test Set for {stack_value}: {accuracy}')

    # predicted_stack = knn_model.predict(X_test)
    # results_df = pd.DataFrame({'Actual Stack': y_test, 'Predicted Stack': predicted_stack})
    # print(results_df)
