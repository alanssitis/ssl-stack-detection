import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier

df = pd.read_csv('../dataset.csv')
df = df.dropna()
unique_stacks = df['stack'].unique()

for stack_value in unique_stacks:
    stack_df = df[df['stack'] == stack_value]
    X = stack_df[['time']]
    y = stack_df['ciphersuite']

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

    n_estimators = 500
    rf_model = RandomForestClassifier(n_estimators=n_estimators, random_state=42)
    rf_model.fit(X_train, y_train)

    accuracy = rf_model.score(X_test, y_test)
    print(f'Model Accuracy on Test Set for {stack_value}: {accuracy}')

    predicted_stack = rf_model.predict(X_test)
    results_df = pd.DataFrame({'Actual Stack': y_test, 'Predicted Stack': predicted_stack})
    print(results_df)