#!/bin/env python3
import subprocess
import sys

def run_executable(executable_path):
  try:
    # subprocess.run automatically attaches the subprocess stdin and stdout to the parent
    result = subprocess.run(executable_path, check=True)
  except FileNotFoundError:
    print(f"Error: The executable '{executable_path[0]}' not found.")
  except subprocess.CalledProcessError as e:
    print(f"Killed... What did you do??")
  except Exception as e:
    print(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
  executable_to_run = ['./chall']
  run_executable(executable_to_run)