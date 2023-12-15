import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score
from data import all_data as df

X = df[['handshakes/s']]
y_lib = df['library']
y_ver = df['version']

X_train, X_test, y_lib_train, y_lib_test, y_ver_train, y_ver_test = train_test_split(
    X, y_lib, y_ver, test_size=0.2, random_state=42
)

svm_library = SVC()
svm_library.fit(X_train, y_lib_train)

y_lib_pred_svm = svm_library.predict(X_test)

lib_and_ver_df_svm = pd.DataFrame({'Predicted Library (SVM)': y_lib_pred_svm, 'Actual Version': y_ver_test, 'handshakes/s': X_test['handshakes/s'].values})

version_models_svm = {}
for library in lib_and_ver_df_svm['Predicted Library (SVM)'].unique():
    subset_data = lib_and_ver_df_svm[lib_and_ver_df_svm['Predicted Library (SVM)'] == library]
    
    X_version = subset_data[['handshakes/s']]
    y_version_subset = subset_data['Actual Version']
    
    svm_version = SVC()
    svm_version.fit(X_version, y_version_subset)
    
    version_models_svm[library] = svm_version

y_ver_pred_svm = lib_and_ver_df_svm.apply(lambda row: version_models_svm[row['Predicted Library (SVM)']].predict([[row['handshakes/s']]]), axis=1)

y_ver_pred_svm = [item for sublist in y_ver_pred_svm for item in sublist]

accuracy_lib_svm = accuracy_score(y_lib_test, y_lib_pred_svm)
accuracy_ver_svm = accuracy_score(y_ver_test, y_ver_pred_svm)

print("Library Accuracy (SVM):", accuracy_lib_svm)
print("Version Accuracy (SVM):", accuracy_ver_svm)

result_df_svm = pd.DataFrame({
    'Actual Library': y_lib_test,
    'Predicted Library (SVM)': y_lib_pred_svm,
    'Actual Version': y_ver_test,
    'Predicted Version (SVM)': y_ver_pred_svm
})
print(result_df_svm)
