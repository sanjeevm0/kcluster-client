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
        return subprocess.check_output("helm template {0} {1}".format(name, tmpdirname), shell=True).decode()

def getFromFile(f):
    if os.path.exists(f):
        return f
    else:
        return yaml.safe_load(f)

if __name__=="__main__":
    import argparse
    import os
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", "-t", help="Template - file or string")
    parser.add_argument("--values", "-v", help="Values - file or string")
    parser.add_argument("--kubectl", "-k", action='store_true', help="Apply to default kube cluster")
    args, rem = parser.parse_known_args()

    if args.template is None or args.values is None:
        # simple test
        print(helmRender("flannel.yaml", {"InterfaceName": "eno1"}))
        exit(0)

    template = getFromFile(args.template)
    values = getFromFile(args.values)
    render = helmRender(template, values)
    print(render)
    if args.kubectl:
        with tempfile.TemporaryDirectory() as tmpdir:
            with open('{0}/kube.yaml'.format(tmpdir), 'w') as fp:
                fp.write(render)
            cmd = 'kubectl apply -f {0}/kube.yaml {1}'.format(tmpdir, " ".join(rem))
            print(cmd)
            os.system(cmd)
