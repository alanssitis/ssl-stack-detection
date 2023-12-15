# from data import all_data as df
# import pandas as pd
# from sklearn.model_selection import train_test_split
# from sklearn.preprocessing import StandardScaler
# from sklearn.neighbors import KNeighborsClassifier

# df = df.dropna(axis=1)

# X = df.drop(['stack'], axis=1)
# y = df['stack']

# scaler = StandardScaler()
# X_scaled = scaler.fit_transform(X)
# X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# k_stack = 15
# knn_stack_model = KNeighborsClassifier(n_neighbors=k_stack)
# knn_stack_model.fit(X_train, y_train)

# accuracy_stack = knn_stack_model.score(X_test, y_test)
# print(f'Stack Prediction Model Accuracy: {accuracy_stack}')

# predicted_stack = knn_stack_model.predict(X_test)
# results_df = pd.DataFrame({'Actual Stack': y_test, 'Predicted Stack': predicted_stack})
# print(results_df)

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.neighbors import KNeighborsClassifier

df = pd.read_csv('../dataset.csv')
df = df.dropna()

X = df[['time']]
y = df['stack']
scaler = MinMaxScaler(axis=1)
X_scaled = scaler.fit_transform(X)
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

k_neighbors = 100
knn_model = KNeighborsClassifier(n_neighbors=k_neighbors)
knn_model.fit(X_train, y_train)

accuracy = knn_model.score(X_test, y_test)
print(f'Model Accuracy on Test Set: {accuracy}')

predicted_stack = knn_model.predict(X_test)
results_df = pd.DataFrame({'Actual Stack': y_test, 'Predicted Stack': predicted_stack})
print(results_df)
