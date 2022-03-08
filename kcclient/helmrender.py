from os import mkdir, system
import shutil
import subprocess
import tempfile
import yaml

chart = {
    'apiVersion': 'v2',
    'name': 'temp',
    'description': 'single file render',
    'version': '0.1',
}

def helmRender(template, values, name="templater"):
    # use helm to render
    with tempfile.TemporaryDirectory() as tmpdirname:
        with open("{0}/Chart.yaml".format(tmpdirname), "w") as fp:
            yaml.safe_dump(chart, fp)
        mkdir("{0}/templates".format(tmpdirname))
        if type(template)==str:
            shutil.copy(template, "{0}/templates/template.yaml".format(tmpdirname))
        else: # dict or list
            with open("{0}/templates/template.yaml".format(tmpdirname), "w") as fp:
                yaml.safe_dump(template, fp)
        with open("{0}/values.yaml".format(tmpdirname), "w") as fp:
            yaml.safe_dump(values, fp)
        #system("helm template {0} {1}".format(name, tmpdirname))
        return subprocess.check_output("helm template {0} {1}".format(name, tmpdirname)).decode()

if __name__=="__main__":
    print(helmRender("flannel.yaml", {"InterfaceName": "eno1"}))
