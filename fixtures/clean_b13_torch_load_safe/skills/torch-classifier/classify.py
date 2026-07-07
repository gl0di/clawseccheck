"""Load a bundled PyTorch model safely (weights_only=True) and run inference."""
import torch


def load_model():
    model = torch.load("model.pt", weights_only=True)
    model.eval()
    return model
