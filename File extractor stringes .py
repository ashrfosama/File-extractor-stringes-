import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog
import binascii

def analyze_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'rb') as file:
            content = file.read()

            # Clear previous content
            for item in table.get_children():
                table.delete(item)
            for item in offset_table.get_children():
                offset_table.delete(item)

            # Display in table
            hex_content = binascii.hexlify(content).decode('utf-8')
            ascii_content = ''.join([chr(byte) if 32 <= byte < 127 else '.' for byte in content])
            for i in range(0, len(hex_content), 32):
                offset = i // 2
                hex_line = ' '.join([hex_content[j:j+2] for j in range(i, i+32, 2)])
                ascii_line = ascii_content[i//2:i//2 + 16]
                table.insert("", "end", values=(f'{offset:08X}', hex_line, ascii_line))

            # Display strings in log area with offsets
            strings = find_strings(content)
            log.delete(1.0, tk.END)  # Clear previous content
            for offset, string in strings:
                log.insert(tk.END, f'{offset:08X}: {string}\n')
                offset_table.insert("", "end", values=(f'{offset:08X}', string))

def find_strings(data):
    min_length = 4  # Minimum length of a string
    strings = []
    string = ""
    offset = 0
    for i, byte in enumerate(data):
        if 32 <= byte < 127:  # ASCII printable characters
            if len(string) == 0:
                offset = i
            string += chr(byte)
        else:
            if len(string) >= min_length:
                strings.append((offset, string))
            string = ""
    if len(string) >= min_length:
        strings.append((offset, string))
    return strings

def save_log():
    log_content = log.get(1.0, tk.END)
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'w') as file:
            file.write(log_content)

# Create the main window
root = tk.Tk()
root.title("Binary File Editor")
root.geometry("1200x800")  # Set window size

# Set transparency
root.attributes('-alpha', 0.90)

# Set the theme to dark orange
root.tk_setPalette(background='#2E2E2E', foreground='#f79400', activeBackground='#FFA500', activeForeground='#f79400')

# Create a button to import the file
import_button = tk.Button(root, text="Import .bin file", command=analyze_file, bg='#FFA500', fg='black')
import_button.pack(pady=10, side=tk.LEFT, padx=10)

# Create a label for AK-TECHNOLOGY TUNING
label = tk.Label(root, text="AK-TECHNOLOGY TUNING", font=("Helvetica", 16, "bold"), bg='#2E2E2E', fg='#f79400')
label.pack(side=tk.LEFT, padx=10)

# Create a frame for the table and scrollbars
table_frame = tk.Frame(root, bg='#2E2E2E', highlightbackground="#FFA500", highlightthickness=2)
table_frame.pack(fill=tk.BOTH, expand=True)

# Create a horizontal scrollbar
xscrollbar = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL)
xscrollbar.pack(side=tk.BOTTOM, fill=tk.X)

# Create a vertical scrollbar
yscrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL)
yscrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Create a table to display analysis results
columns = ("Offset", "Hex", "ASCII")
table = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse", xscrollcommand=xscrollbar.set, yscrollcommand=yscrollbar.set)
for col in columns:
    table.heading(col, text=col)
    table.column(col, anchor="w", width=300)  # Set column anchor to west (left)
table.pack(fill=tk.BOTH, expand=True)

# Set scrollbar commands
xscrollbar.config(command=table.xview)
yscrollbar.config(command=table.yview)

# Set colors and borders
table.configure(style="Treeview")
style = ttk.Style()
style.configure("Treeview", rowheight=25)  # Set row height
style.configure("Treeview.Heading", font=("Helvetica", 12, "bold"), foreground="#f79400", background="#2E2E2E")  # Heading style
style.configure("Treeview", foreground="#f79400", background="#2E2E2E")  # Default cell style
table.tag_configure('oddrow', background='#3E3E3E')
table.tag_configure('evenrow', background='#2E2E2E')

# Add horizontal and vertical lines
style.layout("Treeview.Item", [('Treeitem.padding', {'sticky': 'nswe', 'children': [('Treeitem.indicator', {'side': 'left', 'sticky': ''}), ('Treeitem.image', {'side': 'left', 'sticky': ''}), ('Treeitem.text', {'side': 'left', 'sticky': 'w'})]})])
style.configure("Treeview.Item", background="#2E2E2E", foreground="#f79400")
style.map("Treeview", background=[('selected', '#D38312')])

# Increase font size and change text color to black
style.configure("Treeview", font=("Courier New", 12), foreground="#f79400")

# Create a frame for the log area and the offset table
bottom_frame = tk.Frame(root, bg='#2E2E2E', highlightbackground="#FFA500", highlightthickness=2)
bottom_frame.pack(fill=tk.BOTH, expand=True)

# Create a text widget for logging strings
log_label = tk.Label(bottom_frame, text="Strings:", bg='#2E2E2E', fg='#f79400')
log_label.pack(anchor="w")

log_frame = tk.Frame(bottom_frame, bg='#2E2E2E')
log_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

log = tk.Text(log_frame, bg='#2E2E2E', fg='#f79400')
log.pack(fill=tk.BOTH, expand=True)

# Create scrollbars for the log area
log_xscrollbar = ttk.Scrollbar(log_frame, orient=tk.HORIZONTAL, command=log.xview)
log_xscrollbar.pack(side=tk.BOTTOM, fill=tk.X)
log_yscrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=log.yview)
log_yscrollbar.pack(side=tk.RIGHT, fill=tk.Y)
log.config(xscrollcommand=log_xscrollbar.set, yscrollcommand=log_yscrollbar.set)

# Create a table to display offsets and strings
offset_frame = tk.Frame(bottom_frame, bg='#2E2E2E', highlightbackground="#FFA500", highlightthickness=2)
offset_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

offset_columns = ("Offset", "String")
offset_table = ttk.Treeview(offset_frame, columns=offset_columns, show="headings", selectmode="browse")
for col in offset_columns:
    offset_table.heading(col, text=col)
    offset_table.column(col, anchor="w", width=150)  # Set column anchor to west (left)
offset_table.pack(fill=tk.BOTH, expand=True)

# Set colors and borders for the offset table
offset_table.configure(style="Treeview")
style.configure("Treeview.Heading", font=("Helvetica", 12, "bold"), foreground="#f79400", background="#2E2E2E")  # Heading style
style.configure("Treeview", foreground="#f79400", background="#2E2E2E")  # Default cell style
offset_table.tag_configure('oddrow', background='#3E3E3E')
offset_table.tag_configure('evenrow', background='#2E2E2E')

# Add horizontal and vertical lines for the offset table
style.layout("Treeview.Item", [('Treeitem.padding', {'sticky': 'nswe', 'children': [('Treeitem.indicator', {'side': 'left', 'sticky': ''}), ('Treeitem.image', {'side': 'left', 'sticky': ''}), ('Treeitem.text', {'side': 'left', 'sticky': 'w'})]})])
style.configure("Treeview.Item", background="#2E2E2E", foreground="#f79400")
style.map("Treeview", background=[('selected', '#D38312')])

# Create a button to save the log
save_button = tk.Button(root, text="Save Log", command=save_log, bg='#FFA500', fg='black')
save_button.pack(pady=5)

# Start the GUI event loop
root.mainloop()
