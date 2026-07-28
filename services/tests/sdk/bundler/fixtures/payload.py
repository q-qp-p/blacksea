"""Ordinary script: imports the SDK the obvious way, no bundling awareness."""

from sdk import Client, Config


def main():
    client = Client(Config(token="  T  "))
    print(client.greet("World"))


if __name__ == "__main__":
    main()
