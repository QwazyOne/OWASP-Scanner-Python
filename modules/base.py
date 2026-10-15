from abc import ABC, abstractmethod
from typing import List
from core.models import Target, VulnerabilityResult
from rich.console import Console

console = Console()

class BaseScannerModule(ABC):
   
    #orice modul nou din kali trebuie sa mosteneasca acesta clasa
   
    def __init__(self):
        #meta date despre modul
        self.name = "Base Module"
        self.description = "Generic description"
        self.required_tools = [] # lista de unelte din sistem
    
    @abstractmethod
    def check_prerequisites(self) -> bool:
        pass #"""Verifica daca uneltele necesare sunt instalate in kali"""
    
    
    @abstractmethod
    def run(self, target: Target) -> List[VulnerabilityResult]:
        pass #logica principala de scanare

    def log(self, message: str, level="info"):
        if level == "info":
            console.print(f"[bold blue][info][/bold blue] [{self.name}] {message}")
        elif level == "error":
            console.print(f"[bold red][ERROR][/bold red] [{self.name}] {message}")
        elif level == "success":
            console.print(f"[bold green][SUCCESS][/bold green] [{self.name}] {message}")
          