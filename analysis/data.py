import os
import pandas as pd
import csv

# folder_path = '../data'

# all_data = pd.DataFrame()

# for filename in os.listdir(folder_path):
#     if filename.endswith('.csv'):
#         file_path = os.path.join(folder_path, filename)
#         df = pd.read_csv(file_path)
        
#         df['library'] = os.path.splitext(filename)[0].split('_')[3]

#         df['version'] = os.path.splitext(filename)[0].split('_')[4]
        
#         all_data = pd.concat([all_data, df], ignore_index=True)

# all_data = pd.read_csv('../data/2023_12_13_all_clients_go_server_p70000.csv')

# Specify the path to your CSV file
input_csv_file_path = "../data/2023_12_13_all_clients_go_server_p70000.csv"
output_csv_file_path = "dataset2.csv"

df = pd.read_csv(input_csv_file_path)
print(df.columns)
df_cleaned = df.dropna(axis=1, how='any')
print(df_cleaned.columns)
# with open(input_csv_file_path, mode='r') as file:
#     csv_reader = csv.DictReader(file)
#     new_rows = []

#     # Iterate through rows and create new rows
#     for row in csv_reader:
#         stack = row["stack"]
#         for ciphersuite, time in row.items():
#             if ciphersuite != "stack" and time and time.lower() != 'nan':
#                 new_row = {"stack": stack, "ciphersuite": ciphersuite, "time": time}
#                 new_rows.append(new_row)

new_rows = []
for _, row in df_cleaned.iterrows():
    stack = row["stack"]
    library = stack.split('_')[0]
    
    for ciphersuite, time in row.items():
        if ciphersuite != "stack" and pd.notna(time):
            new_row = {"stack": stack, "library": library, "ciphersuite": ciphersuite, "time": time}
            new_rows.append(new_row)

with open(output_csv_file_path, mode='w', newline='') as file:
    fieldnames = ["stack", "library", "ciphersuite", "time"]
    csv_writer = csv.DictWriter(file, fieldnames=fieldnames)
    csv_writer.writeheader()

    csv_writer.writerows(new_rows)