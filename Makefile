SUBDIRS=login test_sqlite test_postgres

vet:
	for s in ${SUBDIRS}; do echo $${s}; (cd $${s}; go vet ./...); done
#	for s in ${SUBDIRS}; do (echo $s; cd $s; go vet ./...); done


