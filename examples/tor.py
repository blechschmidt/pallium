"""
Example demonstrating the use of the Python interface with Tor.
"""

from pallium.profiles import Profile
from pallium.hops.tor import TorHop
import requests


def check_tor():
    return requests.get('https://check.torproject.org/api/ip').text.strip()


def download_onion_site():
    # noinspection HttpUrlsUsage
    result = requests.get('http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/')
    print('Tor Project onion site status: %d' % result.status_code)


"""
This snippet starts a session. The `execute` function then forks and runs the function inside the fork.
Note that this causes variable changes caused by the function to be invisible to the parent.
This design is required by the nature of unprivileged user namespaces that cannot be left again after joining.
However, you can have the function return a value. The result is then passed to the parent using the pickle module.
"""
print('A Tor session is started. This may take a while ...')
with Profile([TorHop()], quiet=False) as session:
    print(session.execute(check_tor))
    session.execute(download_onion_site)


"""

# The below code will only work with elevated privileges because having joined an unprivileged user namespace, a process
# is unable to leave it again unless the process is privileged.
# Note that in this case enter=True is passed to the profile constructor causing the context manager to join and leave
# the namespaces on enter and on exit respectively.

with Profile([TorHop()], quiet=False, enter=True) as session:
    print(check_tor())
    download_onion_site()

"""


print('Without Tor:')
print(check_tor())
