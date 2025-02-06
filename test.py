import subprocess

def update_from_git():
    """ Mise à jour de l'application depuis GitLab """
    try:
        # Commande pour récupérer les dernières modifications depuis GitLab
        subprocess.run(['git', 'pull', 'origin', 'main'], check=True)
        print("Mise à jour réussie !")
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de la mise à jour : {e}")

if __name__ == '__main__':
    update_from_git()
