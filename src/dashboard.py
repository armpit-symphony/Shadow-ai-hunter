import matplotlib.pyplot as plt

def visualize_risks(risks):
    """Visualize risks with matplotlib."""
    if not risks:
        risks = {'Device1': 0.8, 'Device2': 0.3}  # Mock
    plt.bar(risks.keys(), risks.values())
    plt.title('Risk Levels')
    plt.xlabel('Devices')
    plt.ylabel('Risk Score')
    plt.show()
